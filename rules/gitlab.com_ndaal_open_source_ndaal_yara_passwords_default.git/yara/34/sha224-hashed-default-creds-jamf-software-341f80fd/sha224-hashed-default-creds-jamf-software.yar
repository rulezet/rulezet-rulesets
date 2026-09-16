rule sha224_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fbe85236a7ca7f172a5eeefa880087aa92bdb17cfc40d27d3155b935"
    $a1="76b5686201a3937541a78416639ba95ca8ba8a165f483b686bbea56a"
condition:
    ($a0 and $a1)
}