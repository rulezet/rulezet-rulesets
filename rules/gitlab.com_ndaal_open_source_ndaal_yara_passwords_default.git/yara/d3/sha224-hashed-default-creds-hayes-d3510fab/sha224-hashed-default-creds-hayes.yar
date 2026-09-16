rule sha224_hashed_default_creds_hayes
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hayes."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97334828d53c41129a236c70343723e0a1febb6ca55dcd4197f38df4"
    $a1="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
condition:
    ($a0 and $a1)
}