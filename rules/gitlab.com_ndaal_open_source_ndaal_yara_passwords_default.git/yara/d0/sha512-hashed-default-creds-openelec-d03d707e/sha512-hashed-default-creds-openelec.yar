rule sha512_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="55e91c3cffcd5ac54a3b3b920f344fe0367e83ed8da0bc8a75ca7c3cca39a052866f3bb451d2ef98b5dc2ae8ac03061f82c87e13ac9009a5bb43ead8541a5a47"
    $a1="edc03ae04eb1df672c5619ee07c59c0e24833e8298efcb9c523eb7ee2c9d71ed6e6a61d820019af115ea0e6897768ccfbbe915ac755d4d0a9427e4a71a5eccab"
condition:
    ($a0 and $a1)
}