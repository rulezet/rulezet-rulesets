rule sha224_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a1="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a2="052eb93c022bca225a99cab966bc361080005ea17fa6ace1982c9f6a"
    $a3="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
    $a4="c8237ed786e1430e7a31c50bf3b9206634d35ddfc039c36c58ea0790"
    $a5="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}