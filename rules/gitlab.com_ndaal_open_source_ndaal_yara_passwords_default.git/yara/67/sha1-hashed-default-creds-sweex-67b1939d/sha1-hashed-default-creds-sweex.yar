rule sha1_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c66c09a3d8e31036fd088a1f12aec347b27e078b"
    $a1="2dc63eb51a5eaac95ba3af8b0375a4d783c2248b"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="07c8cd4a6a7d68a2eb83ee0768111f9e7b7931ac"
    $a7="07c8cd4a6a7d68a2eb83ee0768111f9e7b7931ac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}