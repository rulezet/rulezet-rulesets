rule sha3_256_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="156051159e15e8030d0da8e4be70e356c97aa4b6b5e3438861892aa7b470d8ae"
    $a1="156051159e15e8030d0da8e4be70e356c97aa4b6b5e3438861892aa7b470d8ae"
condition:
    ($a0 and $a1)
}