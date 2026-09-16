rule blake2s_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1cb355815059e81b5e3964ade8c91f169bd502f642b8644c25cce562600735ab"
    $a1="1cb355815059e81b5e3964ade8c91f169bd502f642b8644c25cce562600735ab"
    $a2="cb9a3a73a21b1978685a4d332d9ed43042d373b90d961afe5ec5ad7967b1d81e"
    $a3="cb9a3a73a21b1978685a4d332d9ed43042d373b90d961afe5ec5ad7967b1d81e"
    $a4="f64891e4a7b949d2cb83ea124d0a77622a9a134b433204cef38addfb777b43ff"
    $a5="f64891e4a7b949d2cb83ea124d0a77622a9a134b433204cef38addfb777b43ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}