rule sha384_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f9b09b788ff42918863820a324339dd6029b044f3ea3ede4f835581783273f3ff0c6e540029a6f3b6a10164767b4378"
    $a1="7f9b09b788ff42918863820a324339dd6029b044f3ea3ede4f835581783273f3ff0c6e540029a6f3b6a10164767b4378"
condition:
    ($a0 and $a1)
}