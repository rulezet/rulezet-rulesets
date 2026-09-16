rule sha224_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6af85219ad38647ef723dffa2d25e904612e806151eb9f52870c4bff"
    $a1="a5714cb7afa4506a24f05e4d89f5301ba32e2ed0633c1b4363b45546"
    $a2="6af85219ad38647ef723dffa2d25e904612e806151eb9f52870c4bff"
    $a3="4eab176394a6bfefc9fdf817b0168476fbca31c251cd610ce40dea0e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}