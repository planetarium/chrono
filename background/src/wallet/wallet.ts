import Graphql from "../api/graphql";
import { IStorage } from "../storage/index.js";
import {
	ENCRYPTED_WALLET,
	TXS,
	ACCOUNTS,
	Account,
	ACCOUNT_TYPE_WEB3,
	ACCOUNT_TYPE_KMS,
} from "../constants/constants";
import { Account as Signer, RawPrivateKey, PublicKey } from "@planetarium/account";
import {
	BencodexDictionary,
	Value,
	decode,
	encode,
	isDictionary,
} from "@planetarium/bencodex";
import * as ethers from "ethers";
import { Address } from "@planetarium/account";
import { AwsKmsAccount, KMSClient } from "@planetarium/account-aws-kms";
import {
	UnsignedTx,
	encodeSignedTx,
	encodeUnsignedTx,
	signTx,
} from "@planetarium/tx";
import { Lazyable, resolve } from "../utils/lazy";
import { Emitter } from "../event";
import { Buffer } from "buffer";
import { PopupController } from "../controllers/popup";
import { NetworkController } from "../controllers/network";
import { ConfirmationController } from "../controllers/confirmation";
import { MEAD, NCG, TransferAsset, fav } from "@planetarium/lib9c";
import { ConnectionController } from "../controllers/connection";

interface SavedTransactionHistory {
	id: string;
	endpoint: string;
	status: "STAGING";
	action?: string;
	type: string;
	timestamp: number;
	signer: string;
	data: {
		sender: string;
		receiver: string;
		amount: number;
	};
}

export default class Wallet {
	private readonly storage: IStorage;
	private readonly api: Graphql;
	private readonly popup: PopupController;
	private readonly networkController: NetworkController;
	private readonly confirmationController: ConfirmationController;
	private readonly connectionController: ConnectionController;
	private readonly passphrase: Lazyable<string>;
	private readonly emitter: Emitter;
	private readonly origin: string | undefined;
	private readonly canCall: string[];

	/**
	 *
	 * @param {string | () => string} passphrase
	 * @param {string | undefined} origin
	 * @param {import("../event").Emitter} emitter
	 */
	constructor(
		passphrase: Lazyable<string>,
		origin: string | undefined,
		storage: IStorage,
		api: Graphql,
		popupController: PopupController,
		networkController: NetworkController,
		confirmationController: ConfirmationController,
		connectionController: ConnectionController,
		emitter: Emitter | undefined,
	) {
		this.storage = storage;
		this.api = api;
		this.popup = popupController;
		this.networkController = networkController;
		this.confirmationController = confirmationController;
		this.connectionController = connectionController;
		this.passphrase = passphrase;
		this.emitter = emitter;
		this.origin = origin;
		this.canCall = [
			"createSequentialWallet",
			"createPrivateKeyWallet",
			"sendNCG",
			"getPrivateKey",
			"sign",
			"signTx",
			"listAccounts",
			"getPublicKey",
			"connect",
			"isConnected",
			"checkKMSAccount",
		];
	}

	static async createInstance(
		storage: IStorage,
		passphrase: Lazyable<string>,
		emitter: Emitter,
		origin?: string | undefined,
	) {
		const popup = new PopupController();
		const api = await Graphql.createInstance(storage);
		const networkController = new NetworkController(storage, emitter);
		const approvalRequestController = new ConfirmationController(
			storage,
			popup,
		);
		const connectionController = new ConnectionController(storage);
		return new Wallet(
			passphrase,
			origin,
			storage,
			api,
			popup,
			networkController,
			approvalRequestController,
			connectionController,
			emitter,
		);
	}

	canCallExternal(method: string): boolean {
		console.log("@@@@:" + method);
		return this.canCall.indexOf(method) >= 0;
	}
	hexToBuffer(hex: string): Buffer {
		return Buffer.from(
			ethers.utils.arrayify(hex, { allowMissingPrefix: true }),
		);
	}
	decryptWallet(
		encryptedWalletJson: string,
		passphrase: string,
	): ethers.Wallet {
		return ethers.Wallet.fromEncryptedJsonSync(
			encryptedWalletJson,
			passphrase || resolve(this.passphrase),
		);
	}
	async createSequentialWallet(primaryAddress: string, index: number) {
        const stored = await this.storage.secureGet(ENCRYPTED_WALLET + primaryAddress.toLowerCase());
        const { accountType, accountData } = Array.isArray(stored)
            ? { accountType: stored[0], accountData: stored[1] }
            : { accountType: ACCOUNT_TYPE_WEB3, accountData: stored };

        if (accountType === ACCOUNT_TYPE_WEB3) {
            const wallet = ethers.Wallet.fromEncryptedJsonSync(accountData, resolve(this.passphrase));
            const mnemonic = wallet._mnemonic().phrase;
            const newWallet = ethers.Wallet.fromMnemonic(mnemonic, "m/44'/60'/0'/0/" + index);
            const encryptedWallet = await newWallet.encrypt(resolve(this.passphrase));
            const address = newWallet.address;

            return { address, encryptedWallet };
        } else {
            throw new Error("Can't derive new wallet from non Web3 account.");
        }
	}
	async createPrivateKeyWallet(privateKey: string): Promise<{
		address: string;
		encryptedWallet: string;
	}> {
		const wallet = new ethers.Wallet(privateKey);
		const encryptedWallet = await wallet.encrypt(resolve(this.passphrase));
		const address = wallet.address;

		return { address, encryptedWallet };
	}
	async _transferNCG(sender, receiver, amount, nonce, memo?) {
		const signer = await this.getSigner(sender, resolve(this.passphrase));
		const currentNetwork = await this.networkController.getCurrentNetwork();
		const genesisHash = Buffer.from(currentNetwork.genesisHash, "hex");
		const action = new TransferAsset({
			sender: Address.fromHex(sender, true),
			recipient: Address.fromHex(receiver, true),
			amount: fav(NCG, amount),
			memo,
		});

		const unsignedTx: UnsignedTx = {
			signer: sender.toBytes(),
			actions: [action.bencode()],
			updatedAddresses: new Set([]),
			nonce: BigInt(nonce),
			genesisHash,
			publicKey: (await signer.getPublicKey()).toBytes("uncompressed"),
			timestamp: new Date(),
			maxGasPrice: fav(MEAD, 0.00001),
			gasLimit: 4n,
		};

		const signedTx = await signTx(unsignedTx, signer);
		const encodedHex = Buffer.from(encode(encodeSignedTx(signedTx))).toString(
			"hex",
		);
		const { txId, endpoint } = await this.api.stageTx(encodedHex);

		return { txId, endpoint };
	}

	async sendNCG(sender, receiver, amount, nonce) {
		const { txId, endpoint } = await this._transferNCG(
			sender,
			receiver,
			amount,
			nonce,
		);
		const result: SavedTransactionHistory = {
			id: txId,
			endpoint,
			status: "STAGING",
			type: "transfer_asset5",
			timestamp: +new Date(),
			signer: sender,
			data: {
				sender: sender,
				receiver: receiver,
				amount: amount,
			},
		};

		await this.addPendingTxs(result);
		return result;
	}

	async sign(signerAddress: string, actionHex: string): Promise<string> {
		const action = decode(Buffer.from(actionHex, "hex"));
		if (!isDictionary(action)) {
			throw new Error("Invalid action. action must be BencodexDictionary.");
		}

		return this.confirmationController
			.request({
				category: "sign",
				data: {
					signerAddress,
					content: convertBencodexToJSONableType(action),
				},
			})
			.then(async () => {
				const signer = await this.getSigner(signerAddress, resolve(this.passphrase));
				const sender = Address.fromHex(signerAddress);
				const currentNetwork = await this.networkController.getCurrentNetwork();
				const genesisHash = Buffer.from(currentNetwork.genesisHash, "hex");

				const actionTypeId = action.get("type_id");
				const gasLimit =
					typeof actionTypeId === "string" &&
					actionTypeId.startsWith("transfer_asset")
						? BigInt(4)
						: BigInt(1);

				const unsignedTx = {
					signer: sender.toBytes(),
					actions: [action],
					updatedAddresses: new Set([]),
					nonce: BigInt(await this.api.getNextTxNonce(sender.toString())),
					genesisHash,
					publicKey: (await signer.getPublicKey()).toBytes("uncompressed"),
					timestamp: new Date(),
					maxGasPrice: fav(MEAD, 0.00001),
					gasLimit,
				};

				const signedTx = await signTx(unsignedTx, signer);
				return Buffer.from(encode(encodeSignedTx(signedTx))).toString("hex");
			});
	}

	async signTx(signerAddress: string, encodedUnsignedTxHex: string): Promise<string> {
		const encodedUnsignedTxBytes = Buffer.from(encodedUnsignedTxHex, "hex");
		const encodedUnsignedTx = decode(encodedUnsignedTxBytes);

		if (!isDictionary(encodedUnsignedTx)) {
			throw new Error("Invalid unsigned tx");
		}

		const signer = await this.getSigner(signerAddress, resolve(this.passphrase));
		const signature = await signer.sign(encodedUnsignedTxBytes);

		const SIGNATURE_KEY = new Uint8Array([83]);
		const encodedSignedTx = new BencodexDictionary([
			...encodedUnsignedTx,
			[SIGNATURE_KEY, signature.toBytes()],
		]);

		return Buffer.from(encode(encodedSignedTx)).toString("hex");
	}

	async _signTx(signerAddress: string, unsignedTx: UnsignedTx) {
		const signer = await this.getSigner(signerAddress, resolve(this.passphrase));

		return await signTx(unsignedTx, signer);
	}

	async addPendingTxs(tx) {
		let txs = await this.storage.get<SavedTransactionHistory[]>(
			TXS + tx.signer.toLowerCase(),
		);
		if (!txs) {
			txs = [];
		}
		txs.unshift(tx);
		await this.storage.set(TXS + tx.signer.toLowerCase(), txs.splice(0, 100));
	}

	async getPrivateKey(address: string, passphrase: string): Promise<string> {
		const signer = await this.getSigner(address, passphrase);

		if (signer instanceof RawPrivateKey) {
			return Buffer.from((await signer.exportPrivateKey()).toBytes()).toString("hex");
		}

		throw new Error("Can't export private key from other than RawPrivateKey account type.");
	}

	async connect(): Promise<string[]> {
		return this.confirmationController
			.request({
				category: "connect",
				data: { origin: this.origin },
			})
			.then(async (metadata: string[]) => {
				await this.connectionController.connect(
					this.origin,
					metadata.map((x) => Address.fromHex(x, true)),
				);
				this.emitter("connected", metadata);
				return metadata;
			});
	}

	async isConnected(): Promise<boolean> {
		return this.connectionController.isConnectedSite(this.origin);
	}

	async listAccounts(): Promise<Account[]> {
		const accounts = await this.storage.get<Account[]>(ACCOUNTS);
		if (this.origin) {
			const checked: [boolean, Account][] = await Promise.all(
				accounts.map(async (x) => [
					await this.connectionController.isConnected(
						this.origin,
						Address.fromHex(x.address),
					),
					x,
				]),
			);
			return checked.filter((x) => x[0]).map((x) => x[1]);
		}

		console.log(accounts);
		return accounts;
	}

	async getPublicKey(address: string): Promise<string> {
		const signer = await this.getSigner(address, resolve(this.passphrase));
		return (await signer.getPublicKey()).toHex("uncompressed");
	}

	async checkKMSAccount(
		keyId,
		publicKeyHex,
		region,
		accessKeyId,
		secretAccessKey
	  ): Promise<string> {
		const account = createAwsKmsAccount(
			keyId,
			publicKeyHex,
			region,
			accessKeyId,
			secretAccessKey
		);

	    return (await account.getAddress()).toHex();
	  }

	  async getSigner(address: string, passphrase: string): Promise<Signer> {
		const stored = await this.storage.secureGet(
			ENCRYPTED_WALLET + address.toLowerCase()
		);
		const { accountType, accountData } = Array.isArray(stored)
			? { accountType: stored[0], accountData: stored[1] }
			: { accountType: ACCOUNT_TYPE_WEB3, accountData: stored };

		switch (accountType) {
			case ACCOUNT_TYPE_WEB3:
			const wallet = ethers.Wallet.fromEncryptedJsonSync(
				accountData,
				passphrase
			);

			return RawPrivateKey.fromHex(wallet.privateKey.slice(2));

			case ACCOUNT_TYPE_KMS:
			const [keyId, publicKeyHex, region, accessKeyId, secretAccessKey] =
				accountData;

			return createAwsKmsAccount(
				keyId,
				publicKeyHex,
				region,
				accessKeyId,
				secretAccessKey
			);

			default:
				break;
		}
	}
}

function convertBencodexToJSONableType(v: Value) {
	if (v instanceof Array) {
		return v.map(convertBencodexToJSONableType);
	}

	if (isDictionary(v)) {
		const res = {};
		for (const [key, value] of v.entries()) {
			res[convertBencodexToJSONableType(key)] =
				convertBencodexToJSONableType(value);
		}

		return res;
	}

	if (v instanceof Uint8Array) {
		// if (v.every(x => x >= 97 && x <= 122 || x >= 65 && x <= 90)) {
		//   return "\\xFEFF" + Buffer.from(v).toString("utf-8");
		// }

		return "0x" + Buffer.from(v).toString("hex");
	}

	if (typeof v === "string") {
		return "\uFEFF" + v;
	}

	if (typeof v === "bigint") {
		return v.toString();
	}

	return v;
}

function createAwsKmsAccount(
	keyId,
	publicKeyHex,
	region,
	accessKeyId,
	secretAccessKey
)
{
	const kmsClient = new KMSClient({
		region,
		credentials: {
			accessKeyId,
			secretAccessKey
		}
	});
	const publicKey = PublicKey.fromHex(
		publicKeyHex,
		publicKeyHex.startsWith("04") ? "uncompressed" : "compressed"
	);

	return new AwsKmsAccount(keyId, publicKey, kmsClient);
}
