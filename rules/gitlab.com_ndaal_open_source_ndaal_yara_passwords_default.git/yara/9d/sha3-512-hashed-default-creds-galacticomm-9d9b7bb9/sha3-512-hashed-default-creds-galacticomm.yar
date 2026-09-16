rule sha3_512_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b227174b406db0a4f07fd700d219af684c54d4ba7c9d9dd14b4c93d2186580366e42665d34666ff0314a813cfa6d03b21e8f591db2c212116a234c73d74361d"
    $a1="1b227174b406db0a4f07fd700d219af684c54d4ba7c9d9dd14b4c93d2186580366e42665d34666ff0314a813cfa6d03b21e8f591db2c212116a234c73d74361d"
condition:
    ($a0 and $a1)
}