rule sha3_512_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0196a2e6c81abea195bc76e38bd12b3805ae8c89840c504ac84e268efe2746414dd7549bfaa89fc0bab043e7396c69179f7e6d1026d4318139674e5432810c81"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="e8621ad8ebf19aa89cb80fae06ad25f9b65dd048dbd8d4ff715ce95a443e87431c790b7fe8c3ecc0dd83f0f8bd1a413fa38324d68b281e0f904c44e3e68386c6"
    $a3="e17a38b395d339ea705790f3a7275543de32c457376819484dffd4d131b4f76f4075e152ed758f2c4cfa899ada895864fc810257035000a66809b69698204d41"
    $a4="7a98f733f4f2dcb5430eea6cc34ced3396855938f43452215651eeb4cfee490fe585a73224003910df9d2c5dfc121831bea27bfe469f5e04991895bdc6cf3336"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}