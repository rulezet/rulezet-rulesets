rule sha384_hashed_default_creds_myiosoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for myiosoft."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a1="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
condition:
    ($a0 and $a1)
}