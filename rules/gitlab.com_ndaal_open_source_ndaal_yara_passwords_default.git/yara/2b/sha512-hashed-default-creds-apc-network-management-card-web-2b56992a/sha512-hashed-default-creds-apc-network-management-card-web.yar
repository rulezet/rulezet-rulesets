rule sha512_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a1="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a2="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a3="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
    $a4="dda42e49fe107cb5758b7c8ceeb5a094ce219bedfec096f19439705c554d582e658c9813c70246516478cb007ca00aae34a0e62f9e281f12041e8a2d1382a29e"
    $a5="ff3d9d060c06599e083d26bcdffd24b51c68e3a7cd10859d6763701e31dad0debdaee7085b95e7b0c5f9c535d5e031e75e885fde7a6056065fce009f597345c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}