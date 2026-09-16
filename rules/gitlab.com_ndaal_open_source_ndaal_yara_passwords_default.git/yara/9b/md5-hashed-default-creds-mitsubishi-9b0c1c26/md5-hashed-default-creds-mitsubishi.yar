rule md5_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="71778f58b20aa2a5c8963315bd2ee62a"
    $a1="71778f58b20aa2a5c8963315bd2ee62a"
    $a2="4bbf1b91cf6f24c93b0c304f812780c0"
    $a3="4bbf1b91cf6f24c93b0c304f812780c0"
    $a4="d145474c70ae0d64848e6c2d9d2114c5"
    $a5="0aa47932a21b0f470e454737aa24e0a3"
    $a6="ee11cbb19052e40b07aac0ca060c23ee"
    $a7="084e0343a0486ff05530df6c705c8bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}