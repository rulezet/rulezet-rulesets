rule sha3_512_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad82bc8081f726e752f1478a301f4b8856660af1e97e67a069123070a88a770163134e8d2b53d74f2474c06687c2504181884ba307d41a753287945390509675"
    $a1="b9a260a5401fb3e4dcf171db05717188e2132dc786ff8bb20b2de7b6c6c4c00f870ddde06e8f6210b15ef2e615809bd0acc43cd71aefc4cc38043b06730d2ebd"
condition:
    ($a0 and $a1)
}