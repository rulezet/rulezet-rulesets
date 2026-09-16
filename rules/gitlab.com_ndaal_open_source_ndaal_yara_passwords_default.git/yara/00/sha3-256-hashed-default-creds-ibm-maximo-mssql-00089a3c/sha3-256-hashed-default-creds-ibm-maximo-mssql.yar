rule sha3_256_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a468ba8adb0a12b9d9c6edfa7351c2d25f7878641950049ba9c98d7e36744ac3"
    $a1="a468ba8adb0a12b9d9c6edfa7351c2d25f7878641950049ba9c98d7e36744ac3"
    $a2="bf45215dac25fcfa0b851a363c3021abd7362a3ce668ca26484c0133e260f35d"
    $a3="bf45215dac25fcfa0b851a363c3021abd7362a3ce668ca26484c0133e260f35d"
    $a4="139731e7de41debe77d701e52a9ef57b0af0144dbf91d3b8c96cc0dc81df3cab"
    $a5="139731e7de41debe77d701e52a9ef57b0af0144dbf91d3b8c96cc0dc81df3cab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}