rule sha3_256_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a3="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a4="90e6263244bbac7413c1947f2306e13af65ee6507c6d46e3493b276ecc098871"
    $a5="90e6263244bbac7413c1947f2306e13af65ee6507c6d46e3493b276ecc098871"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}