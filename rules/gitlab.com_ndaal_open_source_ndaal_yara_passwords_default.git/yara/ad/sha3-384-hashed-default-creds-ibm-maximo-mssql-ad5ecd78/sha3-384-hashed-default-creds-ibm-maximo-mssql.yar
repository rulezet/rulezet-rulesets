rule sha3_384_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9b1c08f26b202b22c4a215f4d7d719f4419e9b15d443c6d8274d06d2ee632e3316c359bf76db225bd67ae12c70ab781e"
    $a1="9b1c08f26b202b22c4a215f4d7d719f4419e9b15d443c6d8274d06d2ee632e3316c359bf76db225bd67ae12c70ab781e"
    $a2="95ac6d9519cedfc9029373e4edf21d87ff8a9dd2e9fe2741d67773919c380f67d65b662bd6edb751e6f35c622e77cd22"
    $a3="95ac6d9519cedfc9029373e4edf21d87ff8a9dd2e9fe2741d67773919c380f67d65b662bd6edb751e6f35c622e77cd22"
    $a4="ebe28e7a50c5089dc2af3a534e26fbf428428d6a7de0ee81693c7db657968a1d323f0761636874d8e079802b4ee33614"
    $a5="ebe28e7a50c5089dc2af3a534e26fbf428428d6a7de0ee81693c7db657968a1d323f0761636874d8e079802b4ee33614"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}