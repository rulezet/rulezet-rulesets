rule sha1_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="318998ce9cf1a7a05865b60d7a44438ce70bafed"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="5fb413a404020014a4077b14f950a635f08129d3"
    $a3="4bf4982f17517951a1c63a646784fd323cba242c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}