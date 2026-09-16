rule sha224_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e25388fde8290dc286a6164fa2d97e551b53498dcbf7bc378eb1f178"
    $a1="1352d6e48ae7b6b3dd7acdb0f7889e420ae186843ecff6e05bb92840"
    $a2="e25388fde8290dc286a6164fa2d97e551b53498dcbf7bc378eb1f178"
    $a3="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}