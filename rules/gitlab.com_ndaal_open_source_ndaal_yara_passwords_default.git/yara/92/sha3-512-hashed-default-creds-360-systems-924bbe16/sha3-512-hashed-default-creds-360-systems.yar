rule sha3_512_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad0c9f9157129a815aa678c8464c440984c1ff2751ad4fe751af01b647e4213e75e8f1a9bc1a3b04bb5b97ba20617754131ff8accac33ff822a7fb05e92410df"
    $a1="ad0c9f9157129a815aa678c8464c440984c1ff2751ad4fe751af01b647e4213e75e8f1a9bc1a3b04bb5b97ba20617754131ff8accac33ff822a7fb05e92410df"
condition:
    ($a0 and $a1)
}