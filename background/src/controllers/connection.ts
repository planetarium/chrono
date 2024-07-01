import { CONNECTED_SITES } from "../constants/constants";
import { IStorage } from "../storage";
import { Address } from "@planetarium/account";

type Connections = Record<string, string[]>;

export class ConnectionController {
	constructor(
		private readonly storage: IStorage,
	) {}

	async connect(origin: string, addresses: Address[]): Promise<void> {
        const connections = await this.getConnections();
        connections[origin] = addresses.map(x => x.toString());
        await this.setConnections(connections);
	}

	async isConnected(origin: string, address?: Address): Promise<boolean> {
		const connections = await this.getConnections();
		if (!connections.hasOwnProperty(origin)) {
            return false;
        }

        const connectedAddresses = connections[origin];
        return connectedAddresses.find(x => x === address.toString()) !== undefined
	}

	async getConnections(): Promise<Connections> {
		return (await this.storage.get(CONNECTED_SITES)) || {};
	}

	private async setConnections(connections: Connections) {
		console.log("connections", connections);
		await this.storage.set(CONNECTED_SITES, connections);
	}
}
