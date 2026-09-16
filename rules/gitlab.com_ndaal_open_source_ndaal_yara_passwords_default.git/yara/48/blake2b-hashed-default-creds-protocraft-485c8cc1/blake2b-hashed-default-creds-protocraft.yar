rule blake2b_hashed_default_creds_protocraft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for protocraft."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="34ba8044050ef19e8ebf58ffb60690b73f6c4f3be1b8b9509a8a438d55e073a12da31c5ed7ed64006f008d480fd7cb0ca1d27ef95ee332cf10beae4068d75899"
    $a1="33509b6581c62b1ae48efcab4188327c4946fe143cfb141765f6657c1c63dea5b9cd715aab8be2955febf9037b63e23888e523454161ed0ad24277ba80ae54eb"
condition:
    ($a0 and $a1)
}