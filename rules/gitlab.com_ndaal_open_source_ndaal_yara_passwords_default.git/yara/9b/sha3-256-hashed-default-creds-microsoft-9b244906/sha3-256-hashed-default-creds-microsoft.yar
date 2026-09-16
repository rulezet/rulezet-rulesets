rule sha3_256_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a1="8b8d64102829b2979ae2e3ab9ad13a0323bd0c668b79d1b670d8ad647a84c310"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a5="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a6="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a7="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a8="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a9="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a10="cbf1f151f6c9c7a0d5d9b326167853fb6e7d2331d99256b50babab5e154eb6b2"
    $a11="cbf1f151f6c9c7a0d5d9b326167853fb6e7d2331d99256b50babab5e154eb6b2"
    $a12="8c9d71e8d10351d0543301acf51f98a6a5810b16ca66011a7e2f30c804c7ea94"
    $a13="cd961d181710c60c2a168bb3e999dc30db7ff17f23bb7374edc2e529c9ecd1d9"
    $a14="576c21871d58fe2264f6a583c33d0c35ea41bc24a1ec998efde9551886b91ef8"
    $a15="576c21871d58fe2264f6a583c33d0c35ea41bc24a1ec998efde9551886b91ef8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}