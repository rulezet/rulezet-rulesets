rule sha512_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee8f488ab280448501a7522004cb8cd26f29a662519717986b043b812d6475c977c846bb04b03ae90e8182100862b5d6fea16833ea7c6c7f40cf6c16a7a640d7"
    $a1="03e27e1cb5c4dc29a516e09233b4ab6d6521eb98d2da9be0522e197798149f9be841dafc8833c431f295d6ce1d1fe6beadaaa1d31d726d227f0627c82757664b"
condition:
    ($a0 and $a1)
}