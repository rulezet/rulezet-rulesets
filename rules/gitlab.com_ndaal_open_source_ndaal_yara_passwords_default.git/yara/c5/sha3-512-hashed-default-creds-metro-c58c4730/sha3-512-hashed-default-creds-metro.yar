rule sha3_512_hashed_default_creds_metro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metro."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a1="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
condition:
    ($a0 and $a1)
}