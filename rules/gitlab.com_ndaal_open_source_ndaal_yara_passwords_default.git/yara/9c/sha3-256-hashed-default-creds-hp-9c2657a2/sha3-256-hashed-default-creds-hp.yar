rule sha3_256_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="d0d60843b7142bf7732149b080d581f370e034bad57ab3a514523988a254f319"
    $a3="b834aac0f6ecf6e3b2e070b48471bed3f2a4bb18a5c8d793c09f9ddd86738ebd"
    $a4="0afcf13a363f6cb9529764ae95f05aa83a70a0b77e9ca6693174a2d70c06c4e1"
    $a5="d4e45af02b3333234a18a291ab86725cc2aa1d2ad258ab1ca39228e01bc3b7d7"
    $a6="9c04902a5cc7d1ac59e6e541ceaa002df39b2cc379b83462225e31596d317382"
    $a7="d4e45af02b3333234a18a291ab86725cc2aa1d2ad258ab1ca39228e01bc3b7d7"
    $a8="8823face196d1e83888a4c1a0c308676b2ef3d85b9a14e6b4f6d54b536a5c86c"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="9e60db57b96a31d91a6e93b7f4416d257d0b22ab081e6b293e7d23301a9521fd"
    $a11="afec5811ca4b60e82f6b4f88b484edd8420f01539205074dd897fe9003c11c8f"
    $a12="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a13="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a14="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a15="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a16="98776bf06ba2c3fa56a5989a76af49e2d36fd174e3bce234b7808f535375c16b"
    $a17="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}