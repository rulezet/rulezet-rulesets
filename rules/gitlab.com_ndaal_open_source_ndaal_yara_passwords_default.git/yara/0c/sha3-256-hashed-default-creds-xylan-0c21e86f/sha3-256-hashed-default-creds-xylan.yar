rule sha3_256_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="20fa9c8dcc6b58031532bc56585ffdc3718ff844722bdfa37bc6ad76957aaafd"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="20fa9c8dcc6b58031532bc56585ffdc3718ff844722bdfa37bc6ad76957aaafd"
    $a5="add19367953daf9688b7ac2d1fb3cf80e8f158fafa8e7f11f512dd5845578078"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}