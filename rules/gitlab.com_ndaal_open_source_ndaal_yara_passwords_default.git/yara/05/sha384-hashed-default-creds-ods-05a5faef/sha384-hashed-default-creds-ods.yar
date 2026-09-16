rule sha384_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30b5916dad58154ee7a056d6abe0e059c0f5fc2443ba9367ee5619a86c2cf2d450d16781f733e758ac9862fee208c835"
    $a1="30b5916dad58154ee7a056d6abe0e059c0f5fc2443ba9367ee5619a86c2cf2d450d16781f733e758ac9862fee208c835"
condition:
    ($a0 and $a1)
}