rule sha3_256_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="0258bef97afffb99c2403b0584562c4a7ff85cabe5ce4b929260a27fce7bf9f7"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="0c6ac23fb537ec6ad977c5cb7c1f6473ee47c62e1e526de7c1a2f3ce8f0101a9"
    $a9="0a6e90db3a6613fd747b538902881c9abb74be9cf4fe123032d75bb8029ab60b"
    $a10="8630b82c230363dac5b5e7973c7022eb4f2f6f755c288a0a51da9ee0f74d5f5c"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="6fe5638d1985847e15e47f474da06bea0ddb48325c73e603c264a0b394ced51c"
    $a13="6fe5638d1985847e15e47f474da06bea0ddb48325c73e603c264a0b394ced51c"
    $a14="735fc8b9602ccb8c094d21b19a821ba99ce10b0aa1d0d950a84854ff0267dd37"
    $a15="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a16="62db7e6e03cf3b0ab19d2e26879af0638065921b47e382680655fbf5252ec53b"
    $a17="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a18="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a19="210c343c1b7a9382b20a9c52d8e279556331c567b65acee55ff17994d59484ac"
    $a20="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a21="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}