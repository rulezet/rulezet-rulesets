rule sha3_512_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f9139780241176e5b4893e5d4d21b7441a0cf73e8d37d66c12050d7df79e9ce5c6aaa46d245d7c06dc991d0e2b20f2ce92509c0ff8c96f54dedbb37d66181c19"
    $a1="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a2="3bc35cf93f11647d01b47ba9e90b757e7a816d84cc499cb59933e8853cd677673c309d7f45063fadd26c576e1e6385899d53edbd293fcfb0fb68b3e61250c541"
    $a3="a2810f0382736604523e984c8d807de8df281e86703bde676ccb103867ecbe75e47241ef02eb3d5159eeca9508f1284d2ee9c55c96d1e07e04bb0ec0c1cc282f"
    $a4="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a5="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a6="87e5fb944e7225c1bb2a13accae75fde5fa9b257f81bbbfd13d2e314c4549aafd1a2122a512bba1482b5805ed9e8425969c31d995078cfe1f7dc397253c43005"
    $a7="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}