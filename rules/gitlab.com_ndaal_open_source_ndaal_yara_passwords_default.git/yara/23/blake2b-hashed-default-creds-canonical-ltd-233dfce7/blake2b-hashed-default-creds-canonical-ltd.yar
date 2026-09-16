rule blake2b_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de944ee96ff10074bdb88cb3ab6f176416d6a2ba639746742fe4800de11e93001a0922ab7ccce5f1a138b17eab08357ae819d5b64807a7923e51a780cadac431"
    $a1="de944ee96ff10074bdb88cb3ab6f176416d6a2ba639746742fe4800de11e93001a0922ab7ccce5f1a138b17eab08357ae819d5b64807a7923e51a780cadac431"
condition:
    ($a0 and $a1)
}