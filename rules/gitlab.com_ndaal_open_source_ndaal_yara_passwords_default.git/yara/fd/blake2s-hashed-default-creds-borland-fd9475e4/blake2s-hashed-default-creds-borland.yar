rule blake2s_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1017d3fe213d3780bc6515975cd30f1b6cbd03126ac536825b680bd10e198895"
    $a1="b523f9b34e8f40db48650cd29c5da32744d5a6ec9572ef8205fcbcea6bc09bd5"
    $a2="1017d3fe213d3780bc6515975cd30f1b6cbd03126ac536825b680bd10e198895"
    $a3="133fa988725e5b6a1631e8e4244a70f8239138a76449723bedc1f54945cb0d49"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}