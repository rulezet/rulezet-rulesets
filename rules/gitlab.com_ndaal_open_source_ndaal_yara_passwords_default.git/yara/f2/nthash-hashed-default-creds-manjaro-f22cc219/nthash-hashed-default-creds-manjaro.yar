rule nthash_hashed_default_creds_manjaro
{
    meta:
        id = "7TxLZBSpE8HQh01hdxBOyp"
        fingerprint = "05e0c6c67a8c2c1417a71694c6215421bf2995132433b0ba23b44bfcc3e5acf0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a611d159a226d1f27e7fe70daed1bb8b"
    $a1="ce543295d829fd9de48f47008f93ff05"
    $a2="657ebb6de35bea4d20a6b0fa0851b8da"
    $a3="ce543295d829fd9de48f47008f93ff05"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}