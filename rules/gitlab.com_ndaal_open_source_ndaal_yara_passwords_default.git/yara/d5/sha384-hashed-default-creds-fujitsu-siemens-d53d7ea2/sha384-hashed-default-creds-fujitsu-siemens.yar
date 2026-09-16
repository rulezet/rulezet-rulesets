rule sha384_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f93d97d9272a03709b2ce929322f0b40454b250429fb2fb3915b2af17c5385008c4aba82acc81e2223348fa7d3dc224"
    $a1="e36acd1ea702a6d1ad8778fd8bac520654e687acb68c19c6b4520d984fd67416abdefc6a2ef6535184e4a29381b9a7dd"
condition:
    ($a0 and $a1)
}