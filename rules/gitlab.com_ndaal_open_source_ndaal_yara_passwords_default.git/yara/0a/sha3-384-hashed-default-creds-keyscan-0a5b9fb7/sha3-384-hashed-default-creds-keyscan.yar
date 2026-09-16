rule sha3_384_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7c6d71f8510dc81b06844cd1cb12df2519127c1acb33a7c28c48006b7d15f05e4a7b0f00f29e7dce39c50b89f9cde99"
    $a1="a186da0e457eb12ddf70cb4c25f54ce36485667d3a3176974c29e4d3ed75ec769a612281817487a35bb80c6eb69f03cd"
condition:
    ($a0 and $a1)
}