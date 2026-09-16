rule nthash_hashed_default_creds_duhua_telnet
{
    meta:
        id = "7kDS4CGRJCmSlqwlGySpGp"
        fingerprint = "d998399de437a5ab25ceebe205e8c958580a61fffa0f9672332c42db23d64f7b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7bdf5168c785cf4a77d28d25e2e18a48"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7bdf5168c785cf4a77d28d25e2e18a48"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="976e4dde60abb60ef9c05e3c3f441b78"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}