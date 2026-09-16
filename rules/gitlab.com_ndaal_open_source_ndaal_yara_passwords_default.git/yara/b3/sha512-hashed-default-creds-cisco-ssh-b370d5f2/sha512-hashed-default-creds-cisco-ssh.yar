rule sha512_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a1="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a2="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a3="8fb64d78d481ac40eada3c93b77944e2c76d42e8419cbbf7f2aa2fa3ff1c167e51b908f5058bc7977da0afa68094494678ce2dcb343557a8446c7170215c2c42"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}