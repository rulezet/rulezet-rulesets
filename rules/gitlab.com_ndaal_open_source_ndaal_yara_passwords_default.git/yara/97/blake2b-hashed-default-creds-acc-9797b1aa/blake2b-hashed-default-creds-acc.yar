rule blake2b_hashed_default_creds_acc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
    $a1="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
condition:
    ($a0 and $a1)
}