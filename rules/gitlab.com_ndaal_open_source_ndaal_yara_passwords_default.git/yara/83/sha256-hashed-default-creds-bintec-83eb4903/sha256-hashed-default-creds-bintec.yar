rule sha256_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8db24da5855f164a53ed460b0d603468d9a73c1709bfade0b2d131229743647a"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="e2fc622593935b064084169db24fb6ebbae612605b0efe49a768a540d78ea04d"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="1ea442a134b2a184bd5d40104401f2a37fbc09ccf3f4bc9da161c6099be3691d"
    $a5="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}