rule sha224_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="348b2cddbab7d2c685cd8a9c0f33984b8cde2508bc04538712dc3a27"
    $a1="348b2cddbab7d2c685cd8a9c0f33984b8cde2508bc04538712dc3a27"
    $a2="c9974882c14290bd2d91be2c5aa9b8114e4c952066bd143274305ba7"
    $a3="c9974882c14290bd2d91be2c5aa9b8114e4c952066bd143274305ba7"
    $a4="be9304d5db0672df72ff3615a2e7dc97125d9615ff1236cc888c0997"
    $a5="be9304d5db0672df72ff3615a2e7dc97125d9615ff1236cc888c0997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}