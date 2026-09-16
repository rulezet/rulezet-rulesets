rule sha224_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a1="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a4="3ccfe0ad92ed1626819859280b3a54413af3d332c84cbe3d2d93725b"
    $a5="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a6="3ccfe0ad92ed1626819859280b3a54413af3d332c84cbe3d2d93725b"
    $a7="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a8="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
    $a9="08e74fd1a5217257bc135439002d9feeba343848249276662407ffef"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}