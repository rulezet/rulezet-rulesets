rule sha3_512_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03f70d78376b41fe748f5414954cf4cad830dd6ad583c2994b5ebb1bc12d2e028827fce6396bc4f6ab0d584f725748b30629468d87fe4bdd2a37bdf726300066"
    $a1="03f70d78376b41fe748f5414954cf4cad830dd6ad583c2994b5ebb1bc12d2e028827fce6396bc4f6ab0d584f725748b30629468d87fe4bdd2a37bdf726300066"
    $a2="bf04400e21ef16275f0dd185ce0ae499ee0720017dcca34bb4bb526054e76087ab412be48573f84a1cf48a8f7e3bd71ba6008d44cb3b8f350ce4d7163cf5399d"
    $a3="bf04400e21ef16275f0dd185ce0ae499ee0720017dcca34bb4bb526054e76087ab412be48573f84a1cf48a8f7e3bd71ba6008d44cb3b8f350ce4d7163cf5399d"
    $a4="34b16275d8b2157ed28830f3b67135512125b2fc671299374182e50b00ce211f76840aa4451dd3b7364953873f20b04f13b5a0144a4103543aa0cf54d2e72c1d"
    $a5="34b16275d8b2157ed28830f3b67135512125b2fc671299374182e50b00ce211f76840aa4451dd3b7364953873f20b04f13b5a0144a4103543aa0cf54d2e72c1d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}