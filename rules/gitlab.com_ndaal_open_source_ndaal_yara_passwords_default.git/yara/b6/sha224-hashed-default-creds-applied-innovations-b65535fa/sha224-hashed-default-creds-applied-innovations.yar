rule sha224_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68dc33ba37cc8c646e413e57bab0b498bee375bf1ba4ea5371d8392f"
    $a1="68dc33ba37cc8c646e413e57bab0b498bee375bf1ba4ea5371d8392f"
condition:
    ($a0 and $a1)
}