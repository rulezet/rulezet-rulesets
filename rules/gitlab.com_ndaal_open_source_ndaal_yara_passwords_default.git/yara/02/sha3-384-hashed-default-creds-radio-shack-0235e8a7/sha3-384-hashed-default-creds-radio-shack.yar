rule sha3_384_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf9d0665d7e0828c6b69ebeb68dc546b21d2eac58ddba1e6798617b5abada050932c63e88c5e80023825fb9c05f4b034"
    $a1="512ab230fd8feab08a9ffe4521de2b0b28dd973768d7887ff2c421ced7cb1b309be5a01fee57f1f588f204e0b8e75f2d"
condition:
    ($a0 and $a1)
}