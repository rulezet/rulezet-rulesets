rule sha224_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="379a46e85d7be930571ab4ef689f10b258ea99318a014e62274479d9"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="d35e70814fe2e2013fca23dd9b7cb67985f65f4aadd7c7d5d0f4caf9"
    $a3="a16b0181d196e34fc0b662184adcba6e440801e1c3cb7a47cabc162c"
    $a4="026538e5757f5fff4745bd506644010d39776027c1d3b302d4959dd3"
    $a5="101111087b7707e181db649390773370f8b4742746f0e88793b8c27e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}