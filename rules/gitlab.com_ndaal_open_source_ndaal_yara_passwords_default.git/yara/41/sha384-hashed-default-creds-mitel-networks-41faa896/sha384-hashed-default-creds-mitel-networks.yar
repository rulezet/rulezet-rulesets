rule sha384_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e79a2eaf7547512cfab23475185d7fa079191815ada7a2cca619f65c0e5ac472a44bab5ce5395b092b3da1d552595f1"
    $a1="09663513fe0f7bb0ee410fabf7b8d38390cd49a909a88c203277f5a50e44f18280de30e1a0eecb2e0eb2a09c88d65ac9"
    $a2="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a3="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a4="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a5="b358f8f9b56b2a537db92b12d136a64b781b8807ca64a4bba5d0f929ad0a950817d481b880de2cc71c78b84f596da977"
    $a6="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a7="d6a4fc7e74ddcd5854f0e1c8a1f5e9b29390ab0bdc7be6b71eb376697d59b3bb463ed3666d098d9b122c84f34aef8494"
    $a8="7e79a2eaf7547512cfab23475185d7fa079191815ada7a2cca619f65c0e5ac472a44bab5ce5395b092b3da1d552595f1"
    $a9="435ead18f85466e7c16e41caf2d9db2d7fbb1e62e870dad777562002cd7e989d374eef70456662d0f0bdaeb23325a032"
    $a10="7e1e4eae3bdc56266bbfa9963b36b493bd5dfc8eca72a4365b44c4749f1a265346710509e07bec8f70a0c2459b542646"
    $a11="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}