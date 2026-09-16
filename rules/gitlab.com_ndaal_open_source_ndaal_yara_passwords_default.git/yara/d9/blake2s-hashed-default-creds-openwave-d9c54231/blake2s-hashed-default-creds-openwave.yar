rule blake2s_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9fc23fe383d94a682ce7a660ded8f49bcadd21f0afdbd2ee45bece27b06bf62"
    $a1="ee017dfd76a6969bcfb09b3d8ae9a383c70db976d24e997c23cd771e978dadce"
    $a2="7fa8279adfcadd4bdc7502a0393e8f27bee43445b268bec343c81d14a943110c"
    $a3="b7a48923c6d9fedb521d303597779f531e1c2b667b5f128bb9a61d840292111b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}