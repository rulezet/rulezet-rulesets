rule sha224_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9bf26ea864b73a48c7c8eedd41822605a9339a064426cdd6485c182"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="49b929d8c8d228f6a8d06123c4c5c9abc7dd0b0a98af8c0e3e92ec76"
    $a3="49b929d8c8d228f6a8d06123c4c5c9abc7dd0b0a98af8c0e3e92ec76"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}