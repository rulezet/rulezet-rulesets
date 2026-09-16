rule blake2b_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a3="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a4="4cb52c5f42cfbe6a67675d1aba438a50b6f411071de6380d17e89856d99f476c560b3ba2da418eb3dc274a6241fc53b1a0307d7146964b73e953bbd4b58d8837"
    $a5="4cb52c5f42cfbe6a67675d1aba438a50b6f411071de6380d17e89856d99f476c560b3ba2da418eb3dc274a6241fc53b1a0307d7146964b73e953bbd4b58d8837"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}