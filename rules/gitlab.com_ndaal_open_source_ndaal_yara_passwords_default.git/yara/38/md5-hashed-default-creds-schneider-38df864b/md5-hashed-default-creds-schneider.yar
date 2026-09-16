rule md5_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ffaf3fb6d00c83203a331c6355cef06"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="0506af4634df8be56cad7d7a264ae0ac"
    $a3="6f7b7bb7691dc20359e3b96cb292ca5c"
    $a4="825379f09bf22a198d7624e11b954a04"
    $a5="ceabda5d7e8fc88fcadd55a04d8f3422"
    $a6="8be20237be6e10dd226134106a9390ff"
    $a7="e64cfa3fd59e32df57003c7401f48c99"
    $a8="91f9d6ca2c1695bf22a22b2cb6a54489"
    $a9="4c8ce3a1e02483869495ebf94802fa42"
    $a10="2e40ad879e955201df4dedbf8d479a12"
    $a11="2e40ad879e955201df4dedbf8d479a12"
    $a12="e355ff3a4a5960b855abdbe2666e5e1d"
    $a13="2e40ad879e955201df4dedbf8d479a12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}