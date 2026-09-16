rule blake2s_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a1="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a2="a9ffe918d233b301489e98159551a7ead6fa05a96a3148c1ac998aec9ac4dd7d"
    $a3="a9ffe918d233b301489e98159551a7ead6fa05a96a3148c1ac998aec9ac4dd7d"
    $a4="200fbc796d214e93d09679b5547e73badd85b1a31f2d21262aea7f82bb654208"
    $a5="200fbc796d214e93d09679b5547e73badd85b1a31f2d21262aea7f82bb654208"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a8="5117f649a9ea85aa30f5aee09a0350b3276dcd11cff0f372f96f321ca3536dfc"
    $a9="5966fc4f2b086214ecfbbe85022bd4f06e8c38a60fb3120ea219a29165ded62c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}