rule sha3_512_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5db0b6d6a145a4d2648a18f5c24feae7d2e82fe9197122f353a145e4d75346b6977ce57b9b404144641856350e09cb53f706ec1fbc9b637f2a4fe8c1933d1dbb"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="a30add93befd90ffed288e4d443ed7823a8c72415eae79c481ca84bae2db8daac507dc10d77d6e28da4d168a1ce338ab9f7699b81e51ec4be6cfb50c2ffabf67"
    $a3="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a4="d5ac09c53e096a047b6d66036218444e75b0d7462abcf774736dee7cd77ff46ff2539c13bda454da24e0614a51074a99c7cb9f7d4f6a27a790bd63d208fab34d"
    $a5="c56f59716f146eba7b862cf6a1443e68a3cee348bd8a6d51dcaa1ea5c52b41692ebca2e96063db57158e82f789a429d2723b0d84c3a308e198827399448c9090"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}