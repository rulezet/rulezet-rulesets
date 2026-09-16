rule blake2b_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6253051754f33993bff0378422ef21c5929a8704073e44d2488a14fd239399a89f55485601e96d99d8c3de1c0e41e6ea71788d552bbff8e49419aba78114294"
    $a1="6b04b4f75c204b0fe79f81a95624c159b824a2107803b32eef68b10d23406a0fca96c3a0386e587133a0d9688de6551608277865faec3655729b585c76519f99"
condition:
    ($a0 and $a1)
}