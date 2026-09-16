rule sha3_512_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7669b686528cc066cff0c08210e26843c2131daace677c38b031c809b865a3b4c32518494f40df88529ab7e3485d09c5e658165758718617c6467cbff687491"
    $a1="b7669b686528cc066cff0c08210e26843c2131daace677c38b031c809b865a3b4c32518494f40df88529ab7e3485d09c5e658165758718617c6467cbff687491"
condition:
    ($a0 and $a1)
}