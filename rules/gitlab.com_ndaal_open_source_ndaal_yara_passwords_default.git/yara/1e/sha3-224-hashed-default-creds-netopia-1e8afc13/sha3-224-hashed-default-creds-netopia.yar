rule sha3_224_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9baed77c2d840f9d027c100f1f09735d55086271731a4344add77298"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="790e62018c699bfdb1d4df6e2264a7ae469d6c9f5e563745250d6055"
    $a3="790e62018c699bfdb1d4df6e2264a7ae469d6c9f5e563745250d6055"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}