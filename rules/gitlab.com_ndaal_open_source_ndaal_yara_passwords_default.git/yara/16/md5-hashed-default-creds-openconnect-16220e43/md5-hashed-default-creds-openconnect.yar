rule md5_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48d18c2f9253969469c99afae38b7b9c"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="48d18c2f9253969469c99afae38b7b9c"
    $a3="18de90c6da59e445d71eef6ab461cab2"
    $a4="48d18c2f9253969469c99afae38b7b9c"
    $a5="4f5cec75c744bd39b5126debbb7cffb8"
    $a6="48d18c2f9253969469c99afae38b7b9c"
    $a7="a18b52134bf979a780f84eac70578f9e"
    $a8="48d18c2f9253969469c99afae38b7b9c"
    $a9="288682ec5f2450588bb37a4523d11616"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}