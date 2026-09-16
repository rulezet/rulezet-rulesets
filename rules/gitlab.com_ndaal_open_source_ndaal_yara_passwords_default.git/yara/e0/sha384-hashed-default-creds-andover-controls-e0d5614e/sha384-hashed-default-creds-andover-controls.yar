rule sha384_hashed_default_creds_andover_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97fd73987136fc80b8984660725d4fa12c25d6ccd071fa888eaa6e41a77b397c48d77555a642cdf71b6e4f1f549c96f0"
    $a1="97fd73987136fc80b8984660725d4fa12c25d6ccd071fa888eaa6e41a77b397c48d77555a642cdf71b6e4f1f549c96f0"
condition:
    ($a0 and $a1)
}