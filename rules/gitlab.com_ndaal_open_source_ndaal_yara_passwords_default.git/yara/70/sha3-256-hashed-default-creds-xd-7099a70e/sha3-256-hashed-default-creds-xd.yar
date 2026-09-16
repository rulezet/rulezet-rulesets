rule sha3_256_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf2ad0f559e00f422c87db12b02e39ed0084ebb68b245c3c96b15e17f13d9d18"
    $a1="cf2ad0f559e00f422c87db12b02e39ed0084ebb68b245c3c96b15e17f13d9d18"
condition:
    ($a0 and $a1)
}