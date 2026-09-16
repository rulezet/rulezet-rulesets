rule mysql41_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a1="*8272D64B4DB9D7DF622DF834A91F9BEA74C6CE6C"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*3D6EC56BEEA1447C617285798BE126D9F52D1032"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}