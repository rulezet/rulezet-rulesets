rule mysql41_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*01869154DCA1B5BF963A19C99BDA20B04999F03C"
    $a1="*5097B434B08A87DFF711261915F56F32AE813FFD"
    $a2="*01869154DCA1B5BF963A19C99BDA20B04999F03C"
    $a3="*2549C299E9E2C2F48092BA62D830F02F9181AC38"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}