rule sha224_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a2="6b3622227bb6985df16f796f1eda9be9ebab4c08837e1cfb236804b9"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="6b3622227bb6985df16f796f1eda9be9ebab4c08837e1cfb236804b9"
    $a5="6b3622227bb6985df16f796f1eda9be9ebab4c08837e1cfb236804b9"
    $a6="22fad01ae2b72d9abd7321d5c283545bdb79b56cc2a0da5afd42f9c4"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="a2f637211b294a257128cfc2c6b8b278d99d6d7c2df09f5933bdcba4"
    $a9="e3d1008edb1c68d858f4fa6871f2abaa168c041058ae276c065fb63f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}