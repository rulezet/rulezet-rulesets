rule sha3_512_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3275a7674bbaa865b849aebe272e3319470e61ffd7f7b2763c3cb027650a63e4d6a4c23abe7d42a7e65059d9400180041870e5b05815ef4fb8d445448a6a501"
    $a1="95943f0f284edb0cba8061ae51e2eaec0d8b7000d2dde0d43a99b91dfde6dcaa96d34792f38ae4eef41e9e31c52ccf48b718c9e66c2bf6a0c4224d81ac6d139a"
    $a2="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a3="1e60cc099bc0ab00cbffb311120b7ca623df6058beb22ac37f5101883128bd5777e26c52c0efd7e2c2319aeefac74440c653b0af588cc5002850a6d75ad277d7"
    $a4="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a5="0391a30a541b439912bcd9e8ce336224a538c74d3cc61265eb04ada3e8a1fe88c26f02792f56034deb488a8543570be0f5cfd928c0fe3f6a09b5996e3da926b0"
    $a6="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a7="bfbf96e4630b0533b4eb0f54fd32ee4ba4084ef74a7b9c476c12c1e17b3f943dff4b7e8ad15f01278678506d0c33913dcf63919af1b55fdf640b4213ef2b339e"
    $a8="b3275a7674bbaa865b849aebe272e3319470e61ffd7f7b2763c3cb027650a63e4d6a4c23abe7d42a7e65059d9400180041870e5b05815ef4fb8d445448a6a501"
    $a9="32451d9f7852e53f251179963b200457b3f5348e2e44b326b398a957dad44b67eb1b75547647cc02c98d928c4e6944882c30567b69089001e152e25145edfbc5"
    $a10="64bcc739ba5a7eb47d0b9539fd8d36a6a2b86100f91b430e938bf53ef6a4805b5bb99febd6efc818d0132a3b57505106f707478f377e0220689e8eac3d3a51d6"
    $a11="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}