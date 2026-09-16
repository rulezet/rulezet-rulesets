rule blake2b_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="72cf2d94f56d5425fec45bb8c8aaad18141e23a009f9944a2059f890e2e054c5df494c883b4dbf86a0ca7c03100da5277723edd727debd8ee2748cf5e3a5b402"
    $a1="72cf2d94f56d5425fec45bb8c8aaad18141e23a009f9944a2059f890e2e054c5df494c883b4dbf86a0ca7c03100da5277723edd727debd8ee2748cf5e3a5b402"
    $a2="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a3="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
    $a4="a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572"
    $a5="a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}