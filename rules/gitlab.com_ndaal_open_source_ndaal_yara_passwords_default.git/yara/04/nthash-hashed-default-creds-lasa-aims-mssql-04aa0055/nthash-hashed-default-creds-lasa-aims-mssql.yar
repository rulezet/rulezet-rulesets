rule nthash_hashed_default_creds_lasa_aims_mssql
{
    meta:
        id = "4BfOqrN3yCLPj1djQGhWLb"
        fingerprint = "a7edb13daef8a1c28b0fd25038d7ba84e3175164c0e13b9c1043c4c50a6e140d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82c27c0d313e3675b244272e1de39e68"
    $a1="11a01c4a0f2f228796c93fa0ca1a634d"
    $a2="82c27c0d313e3675b244272e1de39e68"
    $a3="68c4c94736a69417e75df41cb7e4a2e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}