rule sha3_512_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a82b24ed65f151463b8d698075e4d8d23f524fae1285d60e38ee6a41c2641699ed49d486c13cba47e402f2812df03f58baafe08506f82fbe490430d476e27b61"
    $a1="a82b24ed65f151463b8d698075e4d8d23f524fae1285d60e38ee6a41c2641699ed49d486c13cba47e402f2812df03f58baafe08506f82fbe490430d476e27b61"
condition:
    ($a0 and $a1)
}