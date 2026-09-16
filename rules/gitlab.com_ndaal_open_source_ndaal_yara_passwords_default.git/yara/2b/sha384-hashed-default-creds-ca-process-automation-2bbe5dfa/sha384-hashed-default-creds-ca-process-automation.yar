rule sha384_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b500949cca23b9b05a05ebacdbc7a6db4f2557ab1772ced1e77f0a2dadcc9c673ff608dd6e40c69d9eae8dd19e864437"
    $a1="b500949cca23b9b05a05ebacdbc7a6db4f2557ab1772ced1e77f0a2dadcc9c673ff608dd6e40c69d9eae8dd19e864437"
condition:
    ($a0 and $a1)
}