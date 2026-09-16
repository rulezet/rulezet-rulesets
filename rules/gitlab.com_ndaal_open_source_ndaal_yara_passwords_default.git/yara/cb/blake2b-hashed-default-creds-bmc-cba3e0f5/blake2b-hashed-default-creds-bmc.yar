rule blake2b_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c5406d0cb9f4c79fd9eb85c8aa6ac104cab80c479fc16d2d67bea490b4c72455c6dfe25c7c00546efe3ab0a2e674f95447f8f10ca28cdd3b37ff26e328fc670"
    $a1="0c5406d0cb9f4c79fd9eb85c8aa6ac104cab80c479fc16d2d67bea490b4c72455c6dfe25c7c00546efe3ab0a2e674f95447f8f10ca28cdd3b37ff26e328fc670"
condition:
    ($a0 and $a1)
}