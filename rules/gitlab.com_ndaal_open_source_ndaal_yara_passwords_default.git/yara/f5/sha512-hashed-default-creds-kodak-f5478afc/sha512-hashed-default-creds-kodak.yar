rule sha512_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d64327c3c5c1a339eb93cd061bbfb20c2dacc8a67b65d73b0da06320d1f6ccbfd110efda25361ae296eb27e23e0e32eb64da4f48e2fa3069ba02cd6bbc7e998"
    $a1="4807c8287291d9d4ac8bd9d673b7a0027a7d2b750b93a2129fc21058f2dec5e9ee8eb1accf0cd53a47694879bf066c49e6c714c015a8ba33d2eb1ebf84e172b3"
    $a2="6d64327c3c5c1a339eb93cd061bbfb20c2dacc8a67b65d73b0da06320d1f6ccbfd110efda25361ae296eb27e23e0e32eb64da4f48e2fa3069ba02cd6bbc7e998"
    $a3="39e7aa3caa773526e546250718ab7ab0b2aa3d0638b7ac7689e5a95232254def975c11eb606f295645f849c4e5d602362daac436af8e40831ddc1aaaf8c4f327"
    $a4="6d64327c3c5c1a339eb93cd061bbfb20c2dacc8a67b65d73b0da06320d1f6ccbfd110efda25361ae296eb27e23e0e32eb64da4f48e2fa3069ba02cd6bbc7e998"
    $a5="e7bb5af8bd4663db22eb55a150bb6040658df4cac017aa369479daeb1042fed754d0ee8ee36694179301853e56166178cff20f4d7941deb8cc76d5fa38f430ae"
    $a6="911b0a07a8cacfebc5f1f45596d67017136c950499fa5b4ff6faffa031f3cec7f197853d1660712c154e1f59c60f682e34ea9b5cbd2d8d5adb0c834f963f30de"
    $a7="99c389f40e8478f52c5180a30965d0cd9c5b7773361b50878876a8718a6a9471f4ad12cb258571ceaef23e7059537c15bcf0433ba218cd815422234afe3d81fd"
    $a8="9fbc985c6ed1181abbdceac999dcf86f3321b4ab6ccb3c5eb3de0d769d2263bd298dd0cfb15c73a74b802b1796b2a6450a9c23d438940f4a84e7b1abb88c0951"
    $a9="9fbc985c6ed1181abbdceac999dcf86f3321b4ab6ccb3c5eb3de0d769d2263bd298dd0cfb15c73a74b802b1796b2a6450a9c23d438940f4a84e7b1abb88c0951"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}