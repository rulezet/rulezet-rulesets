rule sha3_384_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c331cc84ed6e9712c42ec5e710008c3af9a3112113a96e3939b1b83de5ffd62fb5f606cd14c0f26f0ec98d176a0bf53"
    $a1="8b46697d023f1e379053b42ba6b30f9a38bfe50db731cbdf1539a9b52bb9faaa86e4b0a3d3b4a740ecec7babecfdbc36"
condition:
    ($a0 and $a1)
}