rule sha3_224_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a1="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a2="6fb76b0a78cc71b672bf52705613eda1fbc81fc48f52542445b7238f"
    $a3="6fb76b0a78cc71b672bf52705613eda1fbc81fc48f52542445b7238f"
    $a4="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a5="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}