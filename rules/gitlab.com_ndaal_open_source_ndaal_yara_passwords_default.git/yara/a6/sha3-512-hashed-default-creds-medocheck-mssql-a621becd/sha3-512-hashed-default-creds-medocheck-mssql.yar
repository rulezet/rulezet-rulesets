rule sha3_512_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b4f96712290edd94e1e0212c3aa629748e1f8f8247665840361fc484eb655b533bad48052581ecce6b76dd5767d2432bfa492fa7f8bdcad1472c3b937e6ccc3"
    $a1="924e728391cbb8f8819bfd968672715e2b81e289857a46d831130c442e65dac8da730c26ab302e890eb9388c0887c1922d0f10c1d05af1ed593081a350a2d81d"
condition:
    ($a0 and $a1)
}