rule md5_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e0cbf0e62d03796f31da47099682b72b"
    $a1="e0cbf0e62d03796f31da47099682b72b"
    $a2="29297f786f4ad15384c7480c84a9d253"
    $a3="ad42f6697b035b7580e4fef93be20b4d"
    $a4="084e0343a0486ff05530df6c705c8bb4"
    $a5="084e0343a0486ff05530df6c705c8bb4"
    $a6="e3afed0047b08059d0fada10f400c1e5"
    $a7="ae94be3cd532ce4a025884819eb08c98"
    $a8="8f9bfe9d1345237cb3b2b205864da075"
    $a9="29297f786f4ad15384c7480c84a9d253"
    $a10="8f9bfe9d1345237cb3b2b205864da075"
    $a11="cbb11ed87dc8a95d81400c7f33c7c171"
    $a12="8f9bfe9d1345237cb3b2b205864da075"
    $a13="084e0343a0486ff05530df6c705c8bb4"
    $a14="e3afed0047b08059d0fada10f400c1e5"
    $a15="e0cbf0e62d03796f31da47099682b72b"
    $a16="ae94be3cd532ce4a025884819eb08c98"
    $a17="ae94be3cd532ce4a025884819eb08c98"
    $a18="cbb11ed87dc8a95d81400c7f33c7c171"
    $a19="cbb11ed87dc8a95d81400c7f33c7c171"
    $a20="f60a93263fba3ee23b51260f6c39c3e1"
    $a21="cfa5301358b9fcbe7aa45b1ceea088c6"
    $a22="2c17c6393771ee3048ae34d6b380c5ec"
    $a23="efb2a684e4afb7d55e6147fbe5a332ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}