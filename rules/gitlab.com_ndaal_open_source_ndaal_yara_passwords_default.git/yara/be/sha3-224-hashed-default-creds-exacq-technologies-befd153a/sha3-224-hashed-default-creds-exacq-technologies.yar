rule sha3_224_hashed_default_creds_exacq_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5cd84de3618c70e212b5187e497fe07684defed98cf92414c5ea6f6"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="11cccbecc1d93de107ca793d0519a298287f7c6f468cd6ff5dec64b9"
    $a3="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}