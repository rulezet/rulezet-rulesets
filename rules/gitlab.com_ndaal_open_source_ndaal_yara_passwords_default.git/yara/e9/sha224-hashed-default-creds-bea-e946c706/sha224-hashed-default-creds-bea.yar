rule sha224_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="c7e8f969fb2abbbe56a301c5bd65ca0ab772788b274d244a55e5e7f9"
    $a2="36e21f2bf0c4247e491d0fe56b2874f8de7aa584a04e88254cc14bbe"
    $a3="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a4="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a5="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}