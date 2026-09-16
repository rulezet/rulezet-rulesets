rule sha224_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7fb217f198e4e8875fe94ec571fba472477807b65106f871802bb656"
    $a1="5cd7fd4c793de52376f74a016cf373db2426deac143682521f0d7779"
    $a2="09fdbc623941c03d3cc3743c3f4923873e75ab6173375aca0500e2a0"
    $a3="09fdbc623941c03d3cc3743c3f4923873e75ab6173375aca0500e2a0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}