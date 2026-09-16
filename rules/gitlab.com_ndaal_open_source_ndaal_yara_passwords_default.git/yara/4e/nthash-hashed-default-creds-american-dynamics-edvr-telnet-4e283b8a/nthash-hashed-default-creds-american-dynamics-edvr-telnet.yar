rule nthash_hashed_default_creds_american_dynamics_edvr_telnet
{
    meta:
        id = "3iLFFzvbC3fZCJfGi7TGU"
        fingerprint = "fc0e10edf23cbb5b0864cc73ea68b3085108fe2424970eb2b4259d2541cc2feb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for american_dynamics_edvr_telnet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66ec07bc45d2eaf331c307af73fcb3b4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}