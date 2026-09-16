rule blake2s_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f45b3f0eb0c77db94cd9e089c91e4af34cebbf60034df9a3bf0642239af32f8b"
    $a1="4305c8368fb76b838cb16a4334a34499323bef73919dc970d8f13ccdfb42ef9e"
    $a2="e922f7b90d222ccd09d1114614152e9b533f300da2c3c9eb6124af77dff2a528"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="cef0603e0ff8eb1842c0822f0fc3974b996589f8c15d8b82e95561054c29d159"
    $a7="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a8="06b07472610e2f84d641236081940a65d124e8f814c54fe4536b834d70d411f7"
    $a9="27621d65151802229728aad129e062d4b30a3bd77a960bb67d412dfb9d818522"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}