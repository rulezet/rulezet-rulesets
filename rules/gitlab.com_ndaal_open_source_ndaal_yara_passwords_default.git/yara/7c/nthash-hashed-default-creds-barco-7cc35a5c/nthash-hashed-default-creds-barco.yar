rule nthash_hashed_default_creds_barco
{
    meta:
        id = "3HwDK1sdd7ekff2MQ1eMCR"
        fingerprint = "93d65e84379cab59465b07d66bc2a6a2fa13a67858c1ff73771d0106ce241a40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2ce527b69ffe029132dbd5b1260988"
    $a1="9954cc0d55d5d8a131a6232c516eb29d"
condition:
    ($a0 and $a1)
}