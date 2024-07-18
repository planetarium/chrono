import { Address } from "@planetarium/account";
import { RefillButton } from "./RefillButton";
import { useGetAvatarsQuery, useGetTipQuery } from "../graphql/generated/graphql";
import { CreateAvatarButton } from "./CreateAvatarButton";

interface AgentProps {
	agentAddress: Address;
	setTxId: (value: string | null) => void;
}

function Agent({ agentAddress, setTxId }: AgentProps) {
	const {
		data: tipData,
		loading: tipLoading,
		error: tipError,
	} = useGetTipQuery({
		pollInterval: 1000,
	});

	const {
		data: avatarsData,
		loading: avatarsLoading,
		error: avatarsError
	} = useGetAvatarsQuery({
		variables: { agentAddress: agentAddress.toString() },
		pollInterval: 1000,
	});

	if (tipLoading || avatarsLoading) {
		return <p className="mt-8 text-white">Loading...</p>;
	}

	if (tipError || avatarsError) {
		return <p className="mt-8 text-white">Failed to fetch data.</p>;
	}

	const tip = tipData?.nodeStatus?.tip?.index || -1;
	const avatars = avatarsData?.stateQuery?.agent?.avatarStates || [];
	if (avatars.length < 1) {
		return (
			<div>
				<p className="mt-8 text-white">The agent may not have any avatars.</p>
				<CreateAvatarButton
					signer={agentAddress}
					avatarIndex={0}
					setTxId={setTxId}
				/>
			</div>
		);
	}

	const REFILL_INTERVAL = 2550 as const;

	return (
		<div className="flex flex-col mt-8 min-w-full min-h-full justify-center items-center">
			{avatars.map(
				({
					address: avatarAddress,
					name: avatarName,
					actionPoint,
					dailyRewardReceivedIndex,
				}) => (
					<div
						className="p-8 shadow-lg w-4/12 bg-slate-100"
						key={avatarAddress}
					>
						<div className="flex flex-row justify-center items-center gap-4">
							<span className="font-bold">
								{avatarName} ({actionPoint} / 120)
							</span>
							{tip - dailyRewardReceivedIndex > REFILL_INTERVAL ? (
								<RefillButton
									signer={agentAddress}
									avatarAddress={Address.fromHex(avatarAddress)}
									setTxId={setTxId}
								/>
							) : (
								<></>
							)}
						</div>
					</div>
				),
			)}
		</div>
	);
}

export default Agent;
