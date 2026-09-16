rule sha224_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7ffdb4717991146d9a649464f37194f803d6ff39479eb37aedd4d6f"
    $a1="38750cc6599f8a257b9c7332c707b8f10a75d7efa416547fee31cee7"
condition:
    ($a0 and $a1)
}