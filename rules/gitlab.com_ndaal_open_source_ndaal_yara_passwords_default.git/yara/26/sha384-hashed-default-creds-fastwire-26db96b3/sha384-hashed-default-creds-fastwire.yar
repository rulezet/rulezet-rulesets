rule sha384_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52c20a6f7f43271e6489d0a1e243b576ac7ef37245f667bf66f0616409824bec4eeb3542c5e0799f242315b9c3df28fe"
    $a1="125ed130116c43fa22dc63ebd49b74cf79322af6c78f6f0b5b2f3bde9a0138617100a07bb08decac89d16330cd5605e2"
condition:
    ($a0 and $a1)
}