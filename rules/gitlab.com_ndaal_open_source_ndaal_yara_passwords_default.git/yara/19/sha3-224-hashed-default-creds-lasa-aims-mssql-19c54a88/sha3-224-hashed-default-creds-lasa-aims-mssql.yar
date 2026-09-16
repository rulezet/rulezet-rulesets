rule sha3_224_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e61fdcc8efbb8136d3dc046b6e2fe9e1f53418f664b6299d658d6f39"
    $a1="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
    $a2="e61fdcc8efbb8136d3dc046b6e2fe9e1f53418f664b6299d658d6f39"
    $a3="dcd3a40649223daecfa713aeb59a40a4cf65236565af0c564a5d0efd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}