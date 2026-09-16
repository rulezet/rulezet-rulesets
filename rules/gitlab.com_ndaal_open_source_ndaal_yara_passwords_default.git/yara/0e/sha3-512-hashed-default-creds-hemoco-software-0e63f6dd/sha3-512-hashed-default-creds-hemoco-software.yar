rule sha3_512_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb93b0c8257846e988aefae549f07d7f0df48c7629f9d478864914f8dba6b166d35a67e2b68f1ce5c22c2df82d8dd38f1aa946857e4d7e601ffd1ddc2ee01326"
    $a1="0a3988e33920104805988d3219d41605e9153038f81b75ff02818b74aa21642bcf7a1eae1f1125c031a11f40a55c2577e5c48feb1c135514d6345912aa7b30c2"
condition:
    ($a0 and $a1)
}