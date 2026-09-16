rule sha224_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a1="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a2="26cd8a8653b5a2ccacf99920f0be8318e824d19126a79a005beae800"
    $a3="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a4="05eb62f24bed29b0bef10e5eefe60619c0a5cf482e5fd961b05d3aac"
    $a5="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a6="dbcbab776f1ef49f329806c3bf059a7b00636e1ea2679c81be8e660c"
    $a7="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a8="26cd8a8653b5a2ccacf99920f0be8318e824d19126a79a005beae800"
    $a9="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a10="05eb62f24bed29b0bef10e5eefe60619c0a5cf482e5fd961b05d3aac"
    $a11="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}