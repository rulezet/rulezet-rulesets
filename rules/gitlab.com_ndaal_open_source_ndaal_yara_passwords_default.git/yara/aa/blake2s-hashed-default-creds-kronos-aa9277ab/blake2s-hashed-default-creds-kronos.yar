rule blake2s_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26dd7e433abac96b79a89055be055867db4e2bf60ea688eadaf87c139046e149"
    $a1="636c18aaf425ada0f1a5e779a1e37e1e9fb30d0230d3ded4edbddbee51c64676"
condition:
    ($a0 and $a1)
}