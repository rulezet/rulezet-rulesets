rule sha3_384_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2272fa9f41e10bd326a5f9d2bb95ac423fb363465ab640fd442102c896c54784c53906fa961b613734e68dd76b92dc41"
    $a1="2272fa9f41e10bd326a5f9d2bb95ac423fb363465ab640fd442102c896c54784c53906fa961b613734e68dd76b92dc41"
condition:
    ($a0 and $a1)
}