rule sha256_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7c4cb77e2c82be1eac2b6c4444410963be5b4edc55582c8ce17e50364e7ce4c"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="f7c4cb77e2c82be1eac2b6c4444410963be5b4edc55582c8ce17e50364e7ce4c"
    $a3="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a4="52a62f75e5b83b91e706fdd8dfd88d2d6544b824d7767a2a38cd6ad078651a89"
    $a5="5aaec4a266c3827df7d1947ea236207cb83216315efd056b44b9b81cad7aba0a"
    $a6="f7c4cb77e2c82be1eac2b6c4444410963be5b4edc55582c8ce17e50364e7ce4c"
    $a7="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}