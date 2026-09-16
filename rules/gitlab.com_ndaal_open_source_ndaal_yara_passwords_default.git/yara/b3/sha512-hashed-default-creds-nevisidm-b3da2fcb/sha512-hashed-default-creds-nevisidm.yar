rule sha512_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6262e1fb0c0d1f960f160febdeb9c8db4c106b4162ddffeeb2335b924185ca8943a6de7266a7441f4ab1abe364066124987e5690ab8682eb649263041157208"
    $a1="8e8b9a6d0c9f6e51c265b9274709b76c7811be2a35b4d9a203d9274068c36b77ecb8b16f11439187aa5283ee81ce1d735edeb8bc652337b6dec6e1a13f82183f"
condition:
    ($a0 and $a1)
}