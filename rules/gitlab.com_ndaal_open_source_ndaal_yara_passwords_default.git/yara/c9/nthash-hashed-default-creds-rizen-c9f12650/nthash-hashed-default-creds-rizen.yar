rule nthash_hashed_default_creds_rizen
{
    meta:
        id = "2quJAxAtqP8ohEjt5uvU1N"
        fingerprint = "761b8239f67990dafebd0bd0e2cdc27e0e1c995d5ee3131db23bcf706dde7ab0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rizen."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad70819c5bc807280974d80f45982011"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}