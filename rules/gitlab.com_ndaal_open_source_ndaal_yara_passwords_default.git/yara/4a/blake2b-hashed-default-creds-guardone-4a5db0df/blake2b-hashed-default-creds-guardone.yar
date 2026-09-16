rule blake2b_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8545495a00f90df3fd67024713f7764f1a1a57290e791cff49d2e3ca2917442d26eac358d0279075c60ff1d951d889e92dbb8d9c5c74daf4ec686fe5a3669b3a"
    $a1="41965264f09107147961b6403f12de5b1d8953ec7ee249e917acab68724d6c5000c8726c50b40e093a0881eeb4e92c7efec4a9925fab561294bd96092bbd82de"
condition:
    ($a0 and $a1)
}