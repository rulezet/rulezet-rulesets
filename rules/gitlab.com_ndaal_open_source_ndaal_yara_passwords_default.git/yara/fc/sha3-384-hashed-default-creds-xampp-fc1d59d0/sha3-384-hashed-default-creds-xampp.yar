rule sha3_384_hashed_default_creds_xampp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98e4f2b895ce934e5ed2e2ed8768cca3b8a923183c5b4b75fcdea7381c8ce89bf82170438b096d3e96f443cd4854b7c3"
    $a1="0c8898a49c7b35455d8f743a531d120157275b0efad2352b318fd77cb14e786e38944ce5d17f963588ef33918aca44d5"
condition:
    ($a0 and $a1)
}