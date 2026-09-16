rule sha3_224_hashed_default_creds_acc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
    $a1="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
condition:
    ($a0 and $a1)
}