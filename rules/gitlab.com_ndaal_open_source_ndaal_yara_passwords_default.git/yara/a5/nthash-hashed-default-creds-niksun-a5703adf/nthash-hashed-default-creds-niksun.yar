rule nthash_hashed_default_creds_niksun
{
    meta:
        id = "5xoEIzpRNg81a4YuuM7J3D"
        fingerprint = "1fd30bf78b05b01e2d7f017d207a6a1a900408a53d3ac25e1b9a96d3bb840cfb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b636c517f6228573b669000debc59c86"
    $a1="7ecceeb0e39023aaed2c81d35014e531"
condition:
    ($a0 and $a1)
}