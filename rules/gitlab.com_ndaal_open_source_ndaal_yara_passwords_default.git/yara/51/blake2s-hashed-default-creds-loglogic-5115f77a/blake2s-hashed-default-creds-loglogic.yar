rule blake2s_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b829912d3fb7849a324dddf0ddff60fd5e483ec6471d57173e0230a75bfd74d1"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="b829912d3fb7849a324dddf0ddff60fd5e483ec6471d57173e0230a75bfd74d1"
    $a3="ef410e2762842f4c2bce465d7ebb2428b0cf82521424995f6ea41813f39f342e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}