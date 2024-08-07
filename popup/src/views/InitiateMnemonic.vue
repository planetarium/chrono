<template>
  <div class="wrap d-flex  flex-column justify-space-between">
    <div>
      <initiate-header :description="t('keepMnemonicSafeDesc')"></initiate-header>

      <v-card dark outlined>
        <v-card-text class="px-4 pb-0">
          <v-row>
            <v-col class="pa-0">
							<v-tabs dark color="point" center-active v-model="tab" fixed-tabs height="36px">
								<v-tab>{{t('createNewAccount')}}</v-tab>
								<v-tab>{{t('recoverAccount')}}</v-tab>
							</v-tabs>
            </v-col>
          </v-row>

          <v-row>
            <v-col class="pa-2">
							<div v-if="tab == 0" class="mt-4">
								<v-text-field
									v-if="!showMnemonic"
									:label="t('mnemonic')"
									:type="'password'"
									readonly
									multi-line
									dark
									outlined
									background-color="#333"
									v-model="mnemonic"
								/>
								<v-textarea
									v-if="showMnemonic"
									:label="t('mnemonic')"
									readonly
									rows="3"
									dark
									outlined
									background-color="#333"
									v-model="mnemonic"
								/>
								<v-btn
									color="point"
									dark
									outlined
									@click="showMnemonic = !showMnemonic">
									{{ showMnemonic ? t('hideMnemonic') : t('showMnemonic') }}
								</v-btn>
							</div>
							<div v-if="tab == 1" class="mt-4">
								<v-text-field
									v-if="!showRecoverMnemonic"
									:label="t('mnemonicInput')"
									:type="'password'"
									multi-line
									height="128px"
									:error-messages="errorRecoverMnemonic"
									dark
									outlined
									background-color="#333"
									v-model="recoverMnemonic"
								/>
								<v-textarea
									v-if="showRecoverMnemonic"
									:label="t('mnemonicInput')"
									readonly
									rows="3"
									:error-messages="errorRecoverMnemonic"
									dark
									outlined
									background-color="#333"
									v-model="recoverMnemonic"
								/>
								<v-btn
									color="point"
									dark
									outlined
									@click="showRecoverMnemonic = !showRecoverMnemonic">
									{{ showRecoverMnemonic ? t('hideMnemonic') : t('showMnemonic') }}
								</v-btn>
							</div>
            </v-col>
          </v-row>

          <p class="text-left description point--text py-0 my-1 font-weight-bold" style="font-size: 13px;">
            <label>
              <input type="checkbox" v-model="checks[0]" :disabled="loading" />
              {{t('mnemonicNotice1')}}
            </label>
          </p>
          <p class="text-left description point--text py-0 mt-2 font-weight-bold" style="font-size: 13px;">
            <label>
              <input type="checkbox" v-model="checks[1]" :disabled="loading" />
              {{t('mnemonicNotice2')}}
            </label>
          </p>
        </v-card-text>
      </v-card>
    </div>
    <div class="pb-8">
      <div class="d-flex mt-6">
        <v-btn dark x-large
               class="flex-fill point-btn"
               color="pointyellow"
               tabindex="3"
               v-if="tab == 0"
               :disabled="!allChecked"
               @click="start"
               :loading="loading"
        >{{t('doneInitBtn')}}</v-btn>
        <v-btn dark x-large
               class="flex-fill point-btn"
               color="pointyellow"
               tabindex="3"
               v-if="tab == 1"
               :disabled="!allChecked || !recoverMnemonic"
               :loading="loading"
               @click="recoverFromMnemonic"
        >{{t('doRecoverAccount')}}</v-btn>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { markRaw, type Raw } from "vue";
import InitiateHeader from "@/components/InitiateHeader.vue";
import _ from "underscore";
import t from "@/utils/i18n";
import { HDNodeWallet, ethers } from "ethers";
import { defineComponent } from "vue";
import { useAccounts } from "@/stores/account";
import { mapStores } from "pinia";
import { useNetwork } from "@/stores/network";

export default defineComponent({
	name: "InitiateMnemonic",
	components: {
		InitiateHeader,
	},
	data(): {
		checks: [boolean, boolean];
		tab: number;
		mnemonic: string;
		recoverMnemonic: string;
		errorRecoverMnemonic: string | null;
		wallet: Raw<HDNodeWallet> | null;
		loading: boolean;
		showMnemonic: boolean;
		showRecoverMnemonic: boolean;
	} {
		return {
			checks: [false, false],
			tab: 0,
			mnemonic: "",
			recoverMnemonic: "",
			errorRecoverMnemonic: null,
			wallet: null,
			loading: false,
			showMnemonic: false,
			showRecoverMnemonic: false,
		};
	},
	computed: {
		...mapStores(useAccounts, useNetwork),
		allChecked() {
			return _.all(this.checks, (c) => c);
		},
	},
	async created() {
		await this.initiate();
	},
	methods: {
		t,
		async initiate() {
			if (this.$route.query && this.$route.query.mode == "recover") {
				this.tab = 1;
			}
			let passphrase = this.$route.params.passphrase;
			if (passphrase) {
				this.wallet = markRaw(ethers.Wallet.createRandom());
				const m = this.wallet.mnemonic;
				if (!m) {
					throw new Error("HDNodeWallet was failed.");
				}

				this.mnemonic = m.phrase;
			} else {
				await this.$router.replace({ name: "initiate" });
			}
		},
		async recoverFromMnemonic() {
			try {
				this.errorRecoverMnemonic = null;
				let mnemonic = this.recoverMnemonic
					.split(" ")
					.filter((w) => w)
					.map((w) => w.trim())
					.join(" ");

				this.wallet = ethers.Wallet.fromPhrase(mnemonic);
				await this.start();
			} catch (e) {
				this.errorRecoverMnemonic = "invalid mnemonic";
			}
		},
		async start() {
			let passphrase = this.$route.params.passphrase;
			if (passphrase && typeof passphrase === "string" && this.wallet) {
				this.loading = true;
				let encryptedWallet = await this.wallet.encrypt(passphrase);

				await Promise.all([
					this.AccountStore.initAccounts(
						this.wallet.address,
						encryptedWallet,
						passphrase,
					),
					this.NetworkStore.initNetworks(),
				]);
				await this.$router.replace({ name: "index" });
			} else {
				await this.$router.replace({ name: "initiate" });
			}
		},
	},
});
</script>

<style scoped lang="scss">
.logo {
  height: 30px;

  img {
    mix-blend-mode: multiply !important;
  }
}
h1 {
  font-size: 42px;
  line-height: 1.2;
  span {
    display: block;
    font-size: 14px;
    color: #ddd;
  }
}

.v-textarea {
  .v-input__slot {
    fieldset {
      border: 1px solid #666 !important;
      color: #666 !important;
    }
  }
}


</style>
