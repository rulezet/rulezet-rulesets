rule sha3_224_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80782e138450cff5f0eb06091957d6d3ecc81f3a391d0be77028f0c6"
    $a1="748ba8e5f604c11ec9c165103584328b3196753804e8f644bfeb684f"
condition:
    ($a0 and $a1)
}