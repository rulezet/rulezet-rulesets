rule sha256_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da4fae854d1fed67f0d83624582933d87e727eae011bf12437b0f9efcba467f6"
    $a1="3263d518158cfb498c27d83e3bad63ec79453a6bd006980dd27e7f32466a9d3a"
condition:
    ($a0 and $a1)
}