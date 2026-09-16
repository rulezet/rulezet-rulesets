rule sha3_384_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d519af07f31abd35f198f33a6747292f9bee5b533b01df2390d87454ba89dc2732911c4b60864a26a9a1b6c096f18d9b"
    $a1="d519af07f31abd35f198f33a6747292f9bee5b533b01df2390d87454ba89dc2732911c4b60864a26a9a1b6c096f18d9b"
    $a2="d519af07f31abd35f198f33a6747292f9bee5b533b01df2390d87454ba89dc2732911c4b60864a26a9a1b6c096f18d9b"
    $a3="a1fe5f185b6e65143b7b8a37c8a8b2fcf53b58cc4ffe021c6b4b157d8b3a9e69ce6a3c4d7361adb1cf83d947b3b7c4f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}