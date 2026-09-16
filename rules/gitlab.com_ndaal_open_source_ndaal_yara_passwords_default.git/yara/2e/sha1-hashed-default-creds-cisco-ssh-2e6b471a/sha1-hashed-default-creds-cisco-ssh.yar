rule sha1_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a1="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a2="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a3="998e7c5fcf168173985dc94f99a0373ec2b2df34"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}