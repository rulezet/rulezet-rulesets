rule sha3_256_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="337160cd0065da43c33c0df1a7903dd16ed8547ea91733366a614d0072ca5add"
    $a1="6767dd7e79ed2ea1a11ee88be0f0d80590d25697aa2b5d5b8a37421a9bbf625e"
condition:
    ($a0 and $a1)
}