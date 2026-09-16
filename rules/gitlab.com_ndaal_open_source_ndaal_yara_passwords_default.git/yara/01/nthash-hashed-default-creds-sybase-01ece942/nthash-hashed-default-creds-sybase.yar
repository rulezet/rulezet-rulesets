rule nthash_hashed_default_creds_sybase
{
    meta:
        id = "3PQ1QsvmHprnI3eMOsWPEP"
        fingerprint = "8566c6173202c3b24d2528c954cefe0183a6cdc421ea2464f88534d063e2e109"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96003623f29d9684e4c293c0cf97ee09"
    $a1="b10958a558a67f06d02340626b10fd89"
    $a2="9bd8519faf47c80f6c8b0e6a40088d00"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}