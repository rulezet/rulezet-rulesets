rule sha3_512_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fb3e93f9a871989c9a91ab7b4c7c87abfad046463ba9d3aa1fcd01f38d96ffc266b11a8b6d59e41ef26931c82698a7c513dc60ecef489d888566aa17088fdf0"
    $a1="6fb3e93f9a871989c9a91ab7b4c7c87abfad046463ba9d3aa1fcd01f38d96ffc266b11a8b6d59e41ef26931c82698a7c513dc60ecef489d888566aa17088fdf0"
condition:
    ($a0 and $a1)
}