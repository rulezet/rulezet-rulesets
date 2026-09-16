rule sha3_512_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0faff5c8f0e2567fe0de9a71e5e40fe237613bd04ee9b2d10727de17f470e649726997f67e4181a17eaaebf67f745c26a2be333cc3076caa67416fc5600cbac3"
    $a1="f063d11964a795a7a33ba044fcfc8dcbd17a44bbd50538d7deed2ba382f7ba5717bb0f6ae75fea4f37c956ebba811951f476cff0a039e86ae6744a36a102fb34"
condition:
    ($a0 and $a1)
}