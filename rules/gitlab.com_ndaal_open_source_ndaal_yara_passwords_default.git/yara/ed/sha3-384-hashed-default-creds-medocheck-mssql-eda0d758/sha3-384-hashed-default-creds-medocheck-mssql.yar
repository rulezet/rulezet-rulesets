rule sha3_384_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b109743d123aa714871566b503b978c728ca1b72776941fa8774a43d23778e17b89f2f1882d655e6d1209f91186bc98"
    $a1="c481e21469702f0726e4b047d94dc759fb68e72d16db2cc90a3cf21aec62fc0e9cfba9aa92f71521ac484581328f9d9d"
condition:
    ($a0 and $a1)
}