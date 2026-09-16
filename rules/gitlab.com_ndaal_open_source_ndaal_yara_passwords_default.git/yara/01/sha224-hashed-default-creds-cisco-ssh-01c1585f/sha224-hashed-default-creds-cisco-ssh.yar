rule sha224_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a1="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a2="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a3="8eaa349e8a15c4dfa4c30fc6645740d51a69a9727aa77f28d1a8dbff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}