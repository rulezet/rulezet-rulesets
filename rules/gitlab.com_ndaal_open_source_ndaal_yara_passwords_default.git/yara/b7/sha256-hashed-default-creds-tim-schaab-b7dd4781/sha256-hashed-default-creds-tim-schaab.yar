rule sha256_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00810cf8b94d6fcb9c5de484d3bec4187620b3e2876e59aab90d852fe0f18fb6"
    $a1="992345f21b57d68f497b9c5dbf837e060eaf2d8a4894f3f98c0b64de2b13006d"
condition:
    ($a0 and $a1)
}