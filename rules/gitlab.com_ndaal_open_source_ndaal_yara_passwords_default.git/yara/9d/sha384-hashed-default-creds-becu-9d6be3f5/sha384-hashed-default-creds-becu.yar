rule sha384_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fcd8daffe3dcd237ce2635d95d85e88acf35b2ab3ce629f6ef065645006ff34365f0f1f34ede6814f08958cbdca16ca9"
    $a1="c8f4e06ab3c3cf212c77ff2a380eeb0d0d24a89bd4f9388640ca0cf95291e9411c48fada50de313c0558e68120ffb3c3"
condition:
    ($a0 and $a1)
}