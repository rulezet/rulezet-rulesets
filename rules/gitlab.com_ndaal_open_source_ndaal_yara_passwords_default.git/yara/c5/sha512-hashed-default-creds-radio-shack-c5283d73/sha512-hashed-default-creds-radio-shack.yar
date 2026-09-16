rule sha512_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe3b6358428a7d041bbf76e6088ca90133ba9cd34414e3ed8c53eff2bcb2a940164ac3541d4a71a2d566b68f01874aa53440d1a87e2d0433f8b07a898dcccfe7"
    $a1="515d4e81bc825cefa65f8a9cdef035f50b688f7169a2e6cdfbe0e6143e5f5f31919de61dfd323876f49987cb5d9f9f0935d0d70884096a80283776910e76540c"
condition:
    ($a0 and $a1)
}