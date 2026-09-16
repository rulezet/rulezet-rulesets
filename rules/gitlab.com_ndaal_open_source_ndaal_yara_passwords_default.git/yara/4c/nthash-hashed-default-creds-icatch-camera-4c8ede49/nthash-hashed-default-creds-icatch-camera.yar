rule nthash_hashed_default_creds_icatch_camera
{
    meta:
        id = "5FtUMiNCgaCUpAMf5G2mGr"
        fingerprint = "51b30e4ff3e191f52e803bda0cb3e7c9e3728ab79140cd40bc2caafc234c0f29"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for icatch_camera."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32ed87bdb5fdc5e9cba88547376818d4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a5e70a02b73668b5d7b8241abf61741c"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}