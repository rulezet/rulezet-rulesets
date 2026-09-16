rule sha256_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f7924f2b6e8cbe2c109b2ae8dd4c59b37e789f7a5a4467eb95da09694fd4b20"
    $a1="b2023b1968525e566eb9b94d83fef83519916d4ffb49ead80fbfc6ecb970c85d"
    $a2="2f5b8e7bd96ba65f4571804d8ff7b8e01073fe400b368bcc2917e2cd5516bd2f"
    $a3="2f5b8e7bd96ba65f4571804d8ff7b8e01073fe400b368bcc2917e2cd5516bd2f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}