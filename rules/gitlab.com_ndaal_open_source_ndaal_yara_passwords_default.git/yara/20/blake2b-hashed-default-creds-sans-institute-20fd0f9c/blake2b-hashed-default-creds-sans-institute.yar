rule blake2b_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa015702a3f89c20b757ec3d291c9352b62de2260d6840e9d051a20a534f51333cb2ed82f52fe1dad27553498ee1658549ee85133ee7a6fc4bb86f55215e4aee"
    $a1="291d8d9b1a1ac34fea6b238960d0435362fe5f1fed20233a9a7db8a655da1137bb62fc2402bd5a520fc1cfd8085bc983b33c03982ce7e9cfe647352d12751210"
condition:
    ($a0 and $a1)
}