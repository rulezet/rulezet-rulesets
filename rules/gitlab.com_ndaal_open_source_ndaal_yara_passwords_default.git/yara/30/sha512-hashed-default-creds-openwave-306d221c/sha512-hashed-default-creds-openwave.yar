rule sha512_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3721e62bad7215d7a3bd33a0c4fda8a2523d026cf320656c5820ee8ea89447a3e01f05ca430c1a9abf721d4b3f4574dd02cbecaa32deafac2ef59ab73fe41d4b"
    $a1="91a55e21d14029542872b51658931194ca4b0fa4e33518ae38b16ce4ea5eadde6a7c5f6c7587f7449d861c15bc92c70ac9b1c82d60f91753a03f6ea52982084c"
    $a2="e932a76e25d20898510036173c54b53c2d99aef0a50cf8effe45285d25faa5325ee4118e5311cc7a08d26bb0fff26198da62695363250b1f5cd56d7559dcafca"
    $a3="0a67db7f97aeccbbad8cede443d8cba9cd66d3935d47be40b48a93cbb5a1afc61bbf0bae8a8c9654c0789284151da1ccdce97e30034a8e0414db08f512a8366e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}