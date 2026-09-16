rule sha3_512_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a1="0efdfc2bf8076425b343850f2d27409d73e75a87a043fb5753bf5b776552d3a9b215ef69a1bc687fa994cf6e0fbd4430b4eede565ec85ade35536a070423a5ec"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="06a28f02fe8424affd9ee20612a1e59eabdb853908d6ee67f6bc41ffdf696946f675ea1f40a4ee904fc92a6124b0faad30a83295c726008e8858970309cb4501"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}