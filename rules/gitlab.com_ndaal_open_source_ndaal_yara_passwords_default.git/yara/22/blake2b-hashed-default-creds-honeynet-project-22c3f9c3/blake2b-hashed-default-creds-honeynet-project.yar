rule blake2b_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e759101c609f4b740ef80e765ae365b2af502d28946ffdb14a008ba3b8f3b38d22724597db1a2727631e47be95bf3dbc91421426b178885abb756996aa2ed28"
    $a1="b5196bdc9583819e00561ee1a613cdb1b258f31f362e8d3253f413d161616c5ecccd9ac60dd3135ced80657ffc4afa28fca9e7fa96895f8c4c3f263592c8abc9"
    $a2="5e759101c609f4b740ef80e765ae365b2af502d28946ffdb14a008ba3b8f3b38d22724597db1a2727631e47be95bf3dbc91421426b178885abb756996aa2ed28"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}