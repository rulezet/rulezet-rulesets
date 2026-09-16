rule sha512_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4388d32f5d77a84bcea8f3502135bf79bc21deb1fa669e00775cc083a50d15fe3c47dc242f6712f24c831b73426fe7b49ffe032d59663859813f41318008c3d6"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="371da7b035a29070b0ee37c16db51d32af6470d9a201fc80070c7fca6d2264c847fdd3f323a971622c5efffe890f3bf72ba2b1816347522b5b1375ec97b64e33"
    $a3="371da7b035a29070b0ee37c16db51d32af6470d9a201fc80070c7fca6d2264c847fdd3f323a971622c5efffe890f3bf72ba2b1816347522b5b1375ec97b64e33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}