rule sha512_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9b354d67a5ff748e0ef03204a681423a01da37f3cc4d7498485f233ac44d5e22d08b87516a7377d788fbddf033a4ea3b56e0558a8d0bfab48dc5063179fdf05"
    $a1="b648c2fa91d28a64c345769768c9055508a06212ad7e2f0372a6978b8d8b687613b0929aa9e8eae04c5023aecefdc641ca4cc2a5451e1291c541d8efd4681325"
condition:
    ($a0 and $a1)
}