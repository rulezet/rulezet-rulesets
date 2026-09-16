rule sha3_384_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5222ddb86d6061d2c0ef2bbc607271ff6f355d4283fd54267766b88ee186ca93ab0e421f3142755d56f76ee87889cb8c"
    $a1="e34ae819caca9487a6092ff046cd54c1eb14989ac529ef23c3489c5e5045a9d14457bf831839430537d8dd7d86a9eaf8"
condition:
    ($a0 and $a1)
}