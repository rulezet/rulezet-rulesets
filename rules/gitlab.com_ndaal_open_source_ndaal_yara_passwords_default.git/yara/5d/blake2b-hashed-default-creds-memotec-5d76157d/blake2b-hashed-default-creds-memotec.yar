rule blake2b_hashed_default_creds_memotec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for memotec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cb52c5f42cfbe6a67675d1aba438a50b6f411071de6380d17e89856d99f476c560b3ba2da418eb3dc274a6241fc53b1a0307d7146964b73e953bbd4b58d8837"
    $a1="b22293d80dff73f0aa7602df414813f4469a2640b32392a7d71e58505050cd0d730c2e2d31ab37450ab2b1f0f5bfe15f0e5b9d708bc3835187740b189b602848"
condition:
    ($a0 and $a1)
}