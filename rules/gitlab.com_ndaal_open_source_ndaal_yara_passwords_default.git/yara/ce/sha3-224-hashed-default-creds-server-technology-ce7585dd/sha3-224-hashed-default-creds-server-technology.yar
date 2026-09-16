rule sha3_224_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f68e7e2a4528837288778443d4cf829e4cbdd06e71fb04a444147ce"
    $a1="f4ba7815dbdea2769dec2551ca6e74f51b0b7c7d5e332d9adf88e2a6"
    $a2="95bbdd0cacbfb9dc56f5e05fcd3f1b4071cda06f40c667fc590c051c"
    $a3="232636ded5559f4595b1aeeab35d8ae4d2de95408187843f4aa03338"
    $a4="e7a26a48d6b986cdb9bed18646d22642a655dfdf21d793c574199b02"
    $a5="cd741b70ce7dd9539ee135a2e3cd02a2bee076879b4ce62eb234f10a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}