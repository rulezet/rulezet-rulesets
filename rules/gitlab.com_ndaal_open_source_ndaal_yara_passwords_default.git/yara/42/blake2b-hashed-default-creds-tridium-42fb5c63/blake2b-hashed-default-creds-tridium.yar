rule blake2b_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de8e56b27f82b0dfd3a14dd53d9955ed0d18de9ea0da32be30929d3392f81044677a63e4c5d196521409a34e492411db8d425acbd7fc50f20c7ecf185c9f2e2f"
    $a1="172dafad42f86f3cdd7a9b6c220309cd08e6953b11f1c3ec5c539943ff14a2ef48aff5a45ee85ec8190dbc8fbb2c681ebc056e8ee8c7c8b718c779a683e91837"
condition:
    ($a0 and $a1)
}