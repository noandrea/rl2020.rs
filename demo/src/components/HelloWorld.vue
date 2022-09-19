<script setup>
import { ref } from 'vue'
// import init, {
//   init_panic_hook,
//   is_revoked,
//   revoke_credential,
//   reset_credential,
// } from 'rl2020';
// see https://vitejs.dev/guide/features.html#webassembly
// import init from '../../node_modules/rl2020/rl2020_bg.wasm?init';

import * as wasm from 'rl2020';


function hello_w() {
  alert("clicked");
}


function reset(element) {
  element.value = JSON.stringify(element.value, null, 2)
  // let jsids = ["revocation_list", "credential"];
  // jsids.forEach(function (v, i) {
  //   let data = JSON.parse(document.getElementById(v).value);
  //   document.getElementById(v).value = JSON.stringify(data, null, 2);
  // });
  document.getElementById("result").innerHTML = "";
}




</script>



<template>
  <div class="main" style="min-height: 100vh">
    <div class="row">
      <div class="col col-sm-6">
        <button id="btn_is_revoked" v-on:click="hello_w()">Check revocation status</button>
        <button id="revoke_credential">Revoke Credential</button>
        <button id="reset_credential">Reset Credential</button>
      </div>
      <div class="col col-sm-6">
        <h4 id="result"></h4>
      </div>
    </div>
    <div class="row">
      <div class="col col-sm-6">
        <h5>Revocation List Credential</h5>
        <textarea id="revocation_list" style="min-height: 80vh">

        {"@context": [
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
        "credentialSubject": {"id":"https://example.com/credentials/status/3","type":"RevocationList2020","encodedList":"eJztwDEBAAAAwqD1T20MHygAAAAAAAAAAAAAAAAAAADgbUAAAAE="},
        "proof": {}
      }
          
          </textarea>
      </div>
      <div class="col col-sm-6">
        <h5>Generic Credential</h5>
        <textarea id="credential" style="min-height: 80vh">
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
        }
        </textarea>
      </div>
    </div>
  </div>

</template>

<style scoped>
.read-the-docs {
  color: #888;
}
</style>










