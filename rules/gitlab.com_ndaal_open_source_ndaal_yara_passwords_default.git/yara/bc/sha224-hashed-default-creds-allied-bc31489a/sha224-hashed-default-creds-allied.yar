rule sha224_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ccfe0ad92ed1626819859280b3a54413af3d332c84cbe3d2d93725b"
    $a1="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a2="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
    $a3="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}