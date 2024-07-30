import { Address } from "@planetarium/account";
import { useMemo, useState } from "react";
import { useStageTransactionMutation } from "../graphql/generated/graphql";
import { getChronoSdk } from "@planetarium/chrono-sdk";
import { CreateAvatar } from "@planetarium/lib9c";

interface CreateAvatarProps {
    signer: Address;
    avatarIndex: number;

    setTxId: (value: string | null) => void;
}

type CreateAvatarProgress = "None" | "Signing" | "Staging" | "Done";

function createCreateAvatarAction(avatarIndex: number): CreateAvatar {
    return new CreateAvatar({
        index: BigInt(avatarIndex),
        hair: 0n,
        ear: 0n,
        lens: 0n,
        tail: 0n,
        name: `Avatar${avatarIndex}`,
    });
}

export function CreateAvatarButton({ signer, avatarIndex, setTxId }: CreateAvatarProps) {
    const [progress, setProgress] = useState<CreateAvatarProgress>("None");
    const [stage] = useStageTransactionMutation();
    const action = useMemo(() => {
        return createCreateAvatarAction(avatarIndex);
    }, [avatarIndex]);

    const onClick = () => {
        setProgress("Signing");
        const chronoWallet = getChronoSdk();
        if (chronoWallet === undefined) {
            return;
        }

        chronoWallet
            .sign(signer, action)
            .then((tx) => {
                console.log(tx);
                setProgress("Staging");
                return stage({
                    variables: {
                        tx: tx.toString("hex"),
                    },
                }).then(({ data, errors }) => {
                    setProgress("Done");
                    setTxId(data?.stageTransaction || null);
                    console.log(data, errors);
                });
            })
            .catch((e: unknown) => {
                console.error(e);
                setProgress("None");
            });
    };

    if (progress !== "None") {
        return (
            <button
                type="button"
                className="rounded-md bg-black text-white p-3 font-bold"
            >
                {progress}
            </button>
        );
    }

    return (
        <button
            type="button"
            className="rounded-md bg-yellow-400 text-white p-3 font-bold"
            onClick={onClick}
        >
            Create Avatar {avatarIndex}
        </button>
    );
}
