rule sha3_512_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4bc96e21751e17f915f76453074300345275b86a1ed9eb7d6f06a8f2a07596c0f35445b0bc90e5d52e6aac1635653d89d23b73120462822078794c226a59d07d"
    $a1="0f4637af3ed6d5e286930d703f36e5b2ed9f729ddfb02c2bcb8fd09f475689ec6d473a04ae6958f1440f323bc627a0447504505207d1cf81c2ef276f05b63d1e"
condition:
    ($a0 and $a1)
}