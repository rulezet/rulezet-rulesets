rule sha384_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a3="7a9bd2c97c0dac298d32249ecb1dbfa11a112206d1d4ca7019e8a949ee0b21ef5aa21fc1a6ace95894f0cac1bb1f9859"
    $a4="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}