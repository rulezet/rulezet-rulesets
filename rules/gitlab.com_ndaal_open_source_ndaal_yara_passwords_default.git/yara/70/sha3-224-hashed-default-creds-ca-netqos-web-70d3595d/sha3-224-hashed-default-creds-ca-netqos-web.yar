rule sha3_224_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4497d476664c5cdae96ee733ebb8410f41d2532f8c75e02eb9b30235"
    $a1="70a0334d7895281bd14bfb98e788d5ab45bf0afc30901dcadf038e0f"
    $a2="4497d476664c5cdae96ee733ebb8410f41d2532f8c75e02eb9b30235"
    $a3="f0546d72df8036431ab74245d0366432a0af204097cbfc5649ff61dd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}