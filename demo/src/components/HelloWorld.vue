<script>
import {init_panic_hook, is_revoked, reset_credential, revoke_credential} from "rl2020";
export default {
  data() {
    return {
      revocation_list: `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc-revocation-list-2020/v1"
  ],
  "id": "https://example.com/credentials/23894672394",
  "type": [
    "VerifiableCredential",
    "RevocationList2020Credential"
  ],
  "issuer": "did:example:credential-issuer",
  "issued": "2020-04-05T14:27:42Z",
  "credentialSubject": {
    "id": "https://example.com/credentials/status/3",
    "type": "RevocationList2020",
    "encodedList": "eJztwDEBAAAAwqD1T20MHygAAAAAAAAAAAAAAAAAAADgbUAAAAE="
  },
  "proof": {}
}`,
      credential: `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "https://example.com/credentials/23894672394",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "did:example:12345",
  "issued": "2020-04-05T14:27:42Z",
  "credentialStatus": {
    "id": "https://dmv.example.gov/credentials/status/3#7812",
    "type": "RevocationList2020Status",
    "revocationListIndex": 7812,
    "revocationListCredential": "https://example.com/credentials/status/3"
  },
  "credentialSubject": {
    "id": "did:example:abcdefg",
    "type": "Person"
  },
  "proof": {}
}`,
      credentialStatus: "",
      isCredentialRevoked: false,
    }
  },
  methods: {
    parse(data) {
      const newData = JSON.parse(data)
      return JSON.stringify(newData, null, 2)
    },
    reset() {
      this.credential = this.parse(this.credential)
      this.revocation_list = this.parse(this.revocation_list)
    },
    extractCredentialSubject(cred) {
      const data = (JSON.parse(cred))
      console.log(data)
      if (data.credentialSubject) {
        console.log(data.credentialSubject)
        return JSON.stringify(data.credentialSubject)
      }
      console.log("{}")
      return "{}" // eh
    },
    replaceCredentialSubject(cred_str, subj_str) {
      const cred = JSON.parse(cred_str)
      cred.credentialSubject = JSON.parse(subj_str)
      return JSON.stringify(cred)
    },
    checkRevocationStatus() {
      try {
        console.log(this.revocation_list)
        console.log(this.credential)
        const revoked = is_revoked(this.extractCredentialSubject(this.revocation_list), this.credential)
        console.log(revoked)
        if (revoked) {
          this.isCredentialRevoked = true
          this.credentialStatus = "Credential is Revoked"
        } else {
          this.isCredentialRevoked = false
          this.credentialStatus = "Credential is Not Revoked"
        }
      } catch (err) {
        console.log(err)
      }
    },
    revokeCredential() {
      try {
        const res = revoke_credential(this.extractCredentialSubject(this.revocation_list), this.credential)
        console.log("revoke cred res",res)
        const newrev = this.replaceCredentialSubject(this.revocation_list, res)
        this.revocation_list = newrev
        this.reset()
      } catch (err) {
        console.log("failed to revoke credential", err)
        this.credentialStatus = "failed to revoke credential"
        this.isCredentialRevoked = true // TODO: this
      }
    },
    resetCredential() {
      try {
        const res = reset_credential(this.extractCredentialSubject(this.revocation_list), this.credential)
        console.log(res)
        this.revocation_list = this.replaceCredentialSubject(this.revocation_list, res)
        this.reset()
      } catch (err) {
        console.log("failed to revoke credential", err)
        this.credentialStatus = "failed to reset credential"
        this.isCredentialRevoked = true // TODO: this
      }
    }
  },
  beforeMount() {
    init_panic_hook(); // TODO: check
  },
  created() {
    console.log("component was created")
    this.reset()
  }
}
</script>



<template>
  <div class="main" style="min-height: 100vh">
    <div class="row">
      <div class="col col-sm-6">
        <button id="btn_is_revoked" @click="checkRevocationStatus">Check revocation status</button>
        <button id="revoke_credential" @click="revokeCredential">Revoke Credential</button>
        <button id="reset_credential" @click="resetCredential">Reset Credential</button>
      </div>
      <div class="col col-sm-6">
        <h4 id="result" :style="{color: isCredentialRevoked ? 'red' : 'green'}">{{ credentialStatus }}</h4>
      </div>
    </div>

    <div class="row">
      <div class="col col-sm-6">
        <h5>Revocation List Credential</h5>
        <textarea id="revocation_list" style="min-height: 80vh" v-model="revocation_list"/>
      </div>
      <div class="col col-sm-6">
        <h5>Generic Credential</h5>
        <textarea id="credential" style="min-height: 80vh" v-model="credential"/>
      </div>
    </div>
  </div>

</template>

<style scoped>
.read-the-docs {
  color: #888;
}
</style>










