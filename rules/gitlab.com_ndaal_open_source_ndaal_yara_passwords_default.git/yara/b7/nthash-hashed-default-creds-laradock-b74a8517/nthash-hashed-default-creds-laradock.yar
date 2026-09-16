rule nthash_hashed_default_creds_laradock
{
    meta:
        id = "gNksTnSC1qQH7n2Oyowal"
        fingerprint = "df4529f75ed8d10863b479546f3da52b2b301453df9fd00e51ed6ca03bd8f8ee"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for laradock."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="878d8014606cda29677a44efa1353fc7"
    $a1="7d891ab402caf2e89ccdd33ed54333ac"
    $a2="329153f560eb329c0e1deea55e88a1e9"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}