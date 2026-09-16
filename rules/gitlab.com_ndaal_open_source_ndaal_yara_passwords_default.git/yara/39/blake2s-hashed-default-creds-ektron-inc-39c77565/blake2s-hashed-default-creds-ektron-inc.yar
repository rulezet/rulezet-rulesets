rule blake2s_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c988c5a4e5d5f03f9b08121efdb5e0fa3862320a09d41cd45294125bede1eba"
    $a1="8c988c5a4e5d5f03f9b08121efdb5e0fa3862320a09d41cd45294125bede1eba"
    $a2="b894b8ed1a098f68cf79d8e28e51fcd25cf47626db584ec94bb349db66565e20"
    $a3="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}