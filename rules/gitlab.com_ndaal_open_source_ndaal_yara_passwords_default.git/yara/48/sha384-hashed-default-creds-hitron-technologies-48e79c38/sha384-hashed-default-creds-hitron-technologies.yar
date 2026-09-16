rule sha384_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="1dfb43866230d1a92eda371e24aee10b48c0b2e79acc8465bff3e67212e9546a7a148dd3ef6567a4b6fabc8dd64f25f0"
    $a3="3c45ddfb39faf93d4450dec68f2f88c667a146c69a1cacefb93ff12a97fdde7f14ff11bd76ac0498196076bfad00b809"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}