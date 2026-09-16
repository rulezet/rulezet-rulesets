rule sha3_512_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a1="bc99c10c839540dd3d575b40fa86c49c6bc7a8a15f6c362fba775749eb2d897209c829b2e1b1b8f61485ddb41f6ae0e82c2f3c623dcc15fd9641262b3c3bc350"
    $a2="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
    $a3="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}