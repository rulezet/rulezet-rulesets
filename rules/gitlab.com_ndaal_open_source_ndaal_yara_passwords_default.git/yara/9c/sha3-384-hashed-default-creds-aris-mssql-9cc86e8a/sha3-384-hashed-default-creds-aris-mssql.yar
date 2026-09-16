rule sha3_384_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da3e70980cb2c13c83430cef527169ba38c148085f6ff80371126f7f7e8f961befe4569797684faf9ad9d99ce404ba3d"
    $a1="3bce26b2ed0167d339470a48dd6152b09f241f0e404dffb8c7a0caedeb450caf96e8944769f4388645d685d7c08423f1"
condition:
    ($a0 and $a1)
}