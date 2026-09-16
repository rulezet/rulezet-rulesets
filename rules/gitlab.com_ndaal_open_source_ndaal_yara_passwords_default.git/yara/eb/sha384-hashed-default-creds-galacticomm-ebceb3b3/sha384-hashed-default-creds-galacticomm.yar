rule sha384_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d096c43043f44bb12e630ed368598f5386597c3f6292f78deacdbb1de3311efb3be6694c2ab6d5787ee8e5e455aee95"
    $a1="8d096c43043f44bb12e630ed368598f5386597c3f6292f78deacdbb1de3311efb3be6694c2ab6d5787ee8e5e455aee95"
condition:
    ($a0 and $a1)
}