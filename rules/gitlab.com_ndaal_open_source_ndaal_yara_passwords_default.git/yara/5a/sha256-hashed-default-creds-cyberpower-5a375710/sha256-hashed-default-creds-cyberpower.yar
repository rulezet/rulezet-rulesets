rule sha256_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af"
    $a1="b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af"
    $a2="b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af"
    $a3="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}