rule sha512_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50b811112b2d418b9c2f2270a4f97e4947a4c0aa1ec92ae4d78c71f6cc74a1837d6a6bc129ac95f114656f0152678a0ce29070123517e4b1cac2cc8993246786"
    $a1="50b811112b2d418b9c2f2270a4f97e4947a4c0aa1ec92ae4d78c71f6cc74a1837d6a6bc129ac95f114656f0152678a0ce29070123517e4b1cac2cc8993246786"
condition:
    ($a0 and $a1)
}