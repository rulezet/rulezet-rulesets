rule sha256_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="b8d31e852725afb1e26d53bab6095b2bff1749c9275be13ed1c05a56ed31ec09"
    $a3="b8d31e852725afb1e26d53bab6095b2bff1749c9275be13ed1c05a56ed31ec09"
    $a4="b5d95422596277f0c2f91145fecbb57e11a0510fdf6f394e9757515588f680a5"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="9bb04416ad5bd45570cb76e9e909be4bc6c9e8766924154c60f552e60f34021c"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a9="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a10="02cb4b955bb1ddfacebd8fe7d7575c28a9d55e2d67817d13888ad827561c03ea"
    $a11="02cb4b955bb1ddfacebd8fe7d7575c28a9d55e2d67817d13888ad827561c03ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}