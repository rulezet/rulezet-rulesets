rule sha512_hashed_default_creds_globespan_virata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for globespan_virata."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4be8509a64cb9a7319309eda69d8ea7ac73b747309467c95bff4e0dc52892fe3c08e9abfaaab285d564519f5395d5b46a998134558ae54abff99547cb61d0c7f"
    $a1="4be8509a64cb9a7319309eda69d8ea7ac73b747309467c95bff4e0dc52892fe3c08e9abfaaab285d564519f5395d5b46a998134558ae54abff99547cb61d0c7f"
condition:
    ($a0 and $a1)
}