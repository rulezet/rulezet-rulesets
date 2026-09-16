rule sha3_256_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="ae93668c759804fd6f35d12583af33852f87cd0a2bcc0e71653b0de783fa99ec"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a7="c896da5bbd049f5bb56a48cc3058554ad47d6386c640bcedaa8813df2cdcf51f"
    $a8="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a9="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a10="c571dd2139e469c5fe159e58bde1bca4a62e9a843f559c149ec8f69784719635"
    $a11="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}