rule blake2b_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5665e3ed29ccb7016bcd620f16b0be405ac8d19210ff3bee077cfd3080fe33fbf88b052e8de7eea48e61ed2944a44f7a1c82d2cf42bcb48e77cb153c732f9708"
    $a1="33509b6581c62b1ae48efcab4188327c4946fe143cfb141765f6657c1c63dea5b9cd715aab8be2955febf9037b63e23888e523454161ed0ad24277ba80ae54eb"
condition:
    ($a0 and $a1)
}