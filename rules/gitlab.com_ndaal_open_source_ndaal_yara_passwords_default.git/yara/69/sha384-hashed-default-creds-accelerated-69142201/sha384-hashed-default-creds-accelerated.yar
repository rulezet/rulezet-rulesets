rule sha384_hashed_default_creds_accelerated
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accelerated."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74c80d057102786413d6f7b6a92759d249204aea7b4d7eee379bf69652b62180d1598ab045c2db9876432d4d303c0811"
    $a1="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
condition:
    ($a0 and $a1)
}