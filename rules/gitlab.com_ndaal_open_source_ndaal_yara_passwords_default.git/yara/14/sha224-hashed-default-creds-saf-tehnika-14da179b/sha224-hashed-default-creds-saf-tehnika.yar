rule sha224_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52f4d3c7715abdba48b86d9d7d506c17137e68b65ad7ec2915aa70af"
    $a1="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a2="63432c2683187cbfb17ff090d336b78ec31194b5b1a82de9d4048d0a"
    $a3="dde324f09efd3b7450ae469f283947826ab09469ffbf19dc43e7f996"
    $a4="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a5="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a6="98f311a1909f9b2998431a3a599c4d2725a9f7c8458c917df8f1a64f"
    $a7="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}