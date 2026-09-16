rule nthash_hashed_default_creds_bosch
{
    meta:
        id = "3x2lGCC3t4XvOL5PdDg2sH"
        fingerprint = "16cffd8687009f22077cf4c920bd3bdbaa369045c4d08f50c806394ce2ad85fa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f07206c3869bda5acd38a3d923a95d2a"
    $a1="f07206c3869bda5acd38a3d923a95d2a"
    $a2="4f0ef98bb330fe5656d49369f5f9c5f5"
    $a3="4f0ef98bb330fe5656d49369f5f9c5f5"
    $a4="57d583aa46d571502aad4bb7aea09c70"
    $a5="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}