rule blake2s_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ca90c49077c4a25741a4fe8feca7e2afa9d0359282a49a9e83e76f0e4ef4aa0"
    $a1="7ce7bb762c0da6a2decf180c6952bd46c655f209f1f7575a947a68275f751e67"
    $a2="fd04dfd3e89eb170fce660fb16d618cb932cb15103ecc2186d7058edf8e5f5cd"
    $a3="7ce7bb762c0da6a2decf180c6952bd46c655f209f1f7575a947a68275f751e67"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}