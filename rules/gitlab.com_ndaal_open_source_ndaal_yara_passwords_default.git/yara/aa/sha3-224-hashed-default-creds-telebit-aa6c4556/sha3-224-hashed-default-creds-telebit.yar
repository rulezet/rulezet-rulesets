rule sha3_224_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a1="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a2="9d8d2e356e3c878f51ccfbba09de41199b1c71d25bc20e3a806ee3e0"
    $a3="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
    $a4="e1f96d03c34f6a579e09118b4f75614614bc2b255f02ac94cb91cc04"
    $a5="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}