rule nthash_hashed_default_creds_samuel_abels
{
    meta:
        id = "1j33qnybUgHmwwYh0gbKqT"
        fingerprint = "025ca5fd03cd0984fc9c3a3b38c77bace7485e1b5d04202acbda4e3ea31b6413"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samuel_abels."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1)
}