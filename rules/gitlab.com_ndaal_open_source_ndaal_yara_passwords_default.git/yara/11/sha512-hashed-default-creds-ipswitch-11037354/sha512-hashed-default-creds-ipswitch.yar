rule sha512_hashed_default_creds_ipswitch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ipswitch."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="ae56e573be742bdbe49c7f43d3412830e4effa6204d90b9bb0eb9260a595ef5703bdd343df2c785f0e725392761a0a28795f8ba6a4a983624849a8b99a58e720"
    $a3="11bc0d55260149f89c5034109d32cfd62109b19a97bba92a35bb1e49a90b243fc45eaa370c8f517ebc9db6785c4a9c1e1e144ebaf863b46a7969da68f4edad2e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}