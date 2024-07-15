import Graphql from "../api/graphql";
import { IStorage } from "../storage/index.js";
import {
	ENCRYPTED_WALLET,
	TXS,
	ACCOUNTS,
	Account,
} from "../constants/constants";
import { RawPrivateKey } from "@planetarium/account";
import {
	BencodexDictionary,
	Value,
	decode,
	encode,
	isDictionary,
} from "@planetarium/bencodex";
import * as ethers from "ethers";
import { Address } from "@planetarium/account";
import { UnsignedTx, encodeSignedTx, encodeUnsignedTx, signTx } from "@planetarium/tx";
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
			"nextNonce",
			"getPrivateKey",
			"sign",
			"signTx",
			"listAccounts",
			"getPublicKey",
			"connect",
			"isConnected",
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
		const wallet = await this.loadWallet(
			primaryAddress,
			resolve(this.passphrase),
		);

		const mnemonic = wallet._mnemonic().phrase;

		const newWallet = ethers.Wallet.fromMnemonic(
			mnemonic,
			"m/44'/60'/0'/0/" + index,
		);
		const encryptedWallet = await newWallet.encrypt(resolve(this.passphrase));
		const address = newWallet.address;

		return { address, encryptedWallet };
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
	async loadWallet(
		address: string,
		passphrase: string,
	): Promise<ethers.Wallet> {
		const encryptedWallet = await this.storage.secureGet<string>(
			ENCRYPTED_WALLET + address.toLowerCase(),
		);
		return this.decryptWallet(encryptedWallet, passphrase);
	}
	async _transferNCG(sender, receiver, amount, nonce, memo?) {
		const wallet = await this.loadWallet(sender, resolve(this.passphrase));
		const account = RawPrivateKey.fromHex(wallet.privateKey.slice(2));
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
			publicKey: (await account.getPublicKey()).toBytes("uncompressed"),
			timestamp: new Date(),
			maxGasPrice: fav(MEAD, 1),
			gasLimit: 4n,
		};

		const signedTx = await signTx(unsignedTx, account);
		const encodedHex = Buffer.from(encode(encodeSignedTx(signedTx))).toString("hex");
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

	async sign(signer: string, actionHex: string): Promise<string> {
		const action = decode(Buffer.from(actionHex, "hex"));
		if (!isDictionary(action)) {
			throw new Error("Invalid action. action must be BencodexDictionary.");
		}

		return this.confirmationController
			.request({
				category: "sign",
				data: {
					signer,
					content: convertBencodexToJSONableType(action),
				},
			})
			.then(async () => {
				const wallet = await this.loadWallet(signer, resolve(this.passphrase));
				const account = RawPrivateKey.fromHex(wallet.privateKey.slice(2));
				const sender = Address.fromHex(wallet.address);
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
					publicKey: (await account.getPublicKey()).toBytes("uncompressed"),
					timestamp: new Date(),
					maxGasPrice: fav(MEAD, 1),
					gasLimit,
				};

				const signedTx = await this._signTx(signer, unsignedTx);
				return Buffer.from(encode(encodeSignedTx(signedTx))).toString("hex");
			});
	}

	async signTx(signer: string, encodedUnsignedTxHex: string): Promise<string> {
		const encodedUnsignedTxBytes = Buffer.from(encodedUnsignedTxHex, "hex");
		const encodedUnsignedTx = decode(encodedUnsignedTxBytes);

		if (!isDictionary(encodedUnsignedTx)) {
			throw new Error("Invalid unsigned tx");
		}

		const wallet = await this.loadWallet(signer, resolve(this.passphrase));
		const account = RawPrivateKey.fromHex(wallet.privateKey);
		const signature = await account.sign(encodedUnsignedTxBytes);

		const SIGNATURE_KEY = new Uint8Array([83]);
		const encodedSignedTx = new BencodexDictionary([
			...encodedUnsignedTx,
			[SIGNATURE_KEY, signature.toBytes()],
		]);

		return Buffer.from(encode(encodedSignedTx)).toString("hex");
	}

	async _signTx(signer, unsignedTx) {
		const wallet = await this.loadWallet(signer, resolve(this.passphrase));
		const account = RawPrivateKey.fromHex(wallet.privateKey.slice(2));

		return await signTx(unsignedTx, account);
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

	async getPrivateKey(address: string, passphrase): Promise<string> {
		let wallet = await this.loadWallet(address, passphrase);
		return wallet.privateKey;
	}

	async connect(): Promise<string[]> {
		return this.confirmationController
			.request({
				category: "connect",
				data: { origin: this.origin },
			})
			.then(async (metadata: string[]) => {
				await this.connectionController.connect(this.origin, metadata.map(x => Address.fromHex(x, true)))
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
			const checked: [boolean, Account][] = await Promise.all(accounts.map(
				async (x) =>
					[await this.connectionController.isConnected(this.origin, Address.fromHex(x.address)), x]
			));
			return checked.filter(x => x[0]).map(x => x[1]);
		}

		console.log(accounts);
		return accounts;
	}

	async getPublicKey(address: string): Promise<string> {
		const wallet = await this.loadWallet(address, resolve(this.passphrase));
		return wallet.publicKey;
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
