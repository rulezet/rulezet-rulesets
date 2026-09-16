rule mysql41_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FA5F4B6C5A7884CC4E1FE095A59A102D030E35E0"
    $a1="*605E1012A697B9891D3B4A602A92BE50E1DDCC30"
    $a2="*945CD6A678938F77346AC173CA56BC1012E0604E"
    $a3="*945CD6A678938F77346AC173CA56BC1012E0604E"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}