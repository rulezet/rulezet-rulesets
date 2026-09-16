rule blake2s_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="865d0ef3f685de5eccbe7f644228fb3a612c5657bae6da2464cfdfe06b0e6ca9"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="8314c99555738c674dc7c1b1363a6e19c08466a4e7807c279d3a7fbb2212be60"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="3b6f88188f890d6d57a648821f8a11f4b796b891a0626d1244a97a3253ee594a"
    $a5="3b6f88188f890d6d57a648821f8a11f4b796b891a0626d1244a97a3253ee594a"
    $a6="5db25a2ebabbf148ae0af5027e9f3eed87e325b935fce924719af02565800644"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}