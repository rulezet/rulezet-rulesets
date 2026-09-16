rule blake2s_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3534f2aa348f386857bfad959514c74e1598d06c82ce2ce610f09033777cedd4"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="255de72527d9901c4324c7af5a920740097360f284a3de8cd907e0bd91c7bd59"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="df5b62c942121f6226e89bc08949226027803958d6e8f39496d1cfb971493483"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="3534f2aa348f386857bfad959514c74e1598d06c82ce2ce610f09033777cedd4"
    $a9="b9b53865e6e605fe3244198542594c759db8a2c7f77f8ec6ef1400664dfc6c84"
    $a10="b29d405f772295c6b2be416d3cf56c95b67bf07ec5b42d0d597dc90b98806930"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="f7d6d802b1b0d6bda7d6a87d0ce4e0d1b9e9e7800d064c5f832714d578442a95"
    $a13="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a14="c07781b352d6b22914b99df930dd6129be5095a9b04763e01c119cf15d4e3cea"
    $a15="61395674c65294b533cc20e5ee0614e0d98747d496cef7f269417aecbb64d16b"
    $a16="574c6e7b47a83822ac14a06a4582ce71287771c20879c08066b4f6ce416c7728"
    $a17="e7b7368b8bad45b6f71a3b6eed4e61fdf671a9311b9fff3400913925112cb36b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}