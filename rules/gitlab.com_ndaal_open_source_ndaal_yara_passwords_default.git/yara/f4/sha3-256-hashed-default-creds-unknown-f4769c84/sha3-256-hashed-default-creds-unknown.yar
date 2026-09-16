rule sha3_256_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47ace37ace27763fd73f6ba4da94d079e936ea911b53ff796d6a0bfc8b4edebf"
    $a1="47ace37ace27763fd73f6ba4da94d079e936ea911b53ff796d6a0bfc8b4edebf"
    $a2="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a3="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a4="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
    $a5="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}