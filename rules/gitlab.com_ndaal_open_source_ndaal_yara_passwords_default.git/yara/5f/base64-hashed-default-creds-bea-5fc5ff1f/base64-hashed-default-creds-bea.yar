rule base64_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="am9l"
    $a1="cGFzc3dvcmQ="
    $a2="c3lzdGVt"
    $a3="c2VjdXJpdHk="
    $a4="c3lzdGVt"
    $a5="d2VibG9naWM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}