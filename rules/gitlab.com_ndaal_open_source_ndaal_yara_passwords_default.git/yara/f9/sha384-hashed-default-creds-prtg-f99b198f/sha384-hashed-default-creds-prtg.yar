rule sha384_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c19698a6ef429e1018159ecd7bba601844763279bf0886f7ee60b3ba67405a31ee2f1e25b129f2b3a94f6a78ed573a4"
    $a1="4c19698a6ef429e1018159ecd7bba601844763279bf0886f7ee60b3ba67405a31ee2f1e25b129f2b3a94f6a78ed573a4"
condition:
    ($a0 and $a1)
}