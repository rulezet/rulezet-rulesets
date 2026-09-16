rule sha384_hashed_default_creds_stuccoboy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18831487ce39551b439095ccef32c8919b11ce12453d11845bc69db5e9e0b5e3f86aa216b406af95f5159adcacbe1428"
    $a1="0ff95eb4231cf9597a637d687c3a73e7e26508dae50a7b551f9504f9a3cb1fc1270787d2912477ca83bec4dd00c20ecc"
condition:
    ($a0 and $a1)
}