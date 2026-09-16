rule sha3_512_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52f485fd1daa838ce4220e8803a15c3dfefd90266dcf360b8219f481ef6e8c293067c35f97b15901240c264a6513070fb7a31241f8aaa2120ded3f9ecdf5ded3"
    $a1="52f485fd1daa838ce4220e8803a15c3dfefd90266dcf360b8219f481ef6e8c293067c35f97b15901240c264a6513070fb7a31241f8aaa2120ded3f9ecdf5ded3"
condition:
    ($a0 and $a1)
}