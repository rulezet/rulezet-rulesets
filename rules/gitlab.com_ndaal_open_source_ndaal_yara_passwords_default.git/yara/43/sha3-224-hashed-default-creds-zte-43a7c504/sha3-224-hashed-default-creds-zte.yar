rule sha3_224_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3870ae613631953c064dc90cdd84d9ba0394da10837533cfc57b0ce9"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="4e9b94a7b9bfd0587eb08ecce05e6891690fc74096bf12f5f252eb3d"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a5="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a6="9cd34d2002e0842320aafc357167e172a11f3151529f7a18a5c40e1d"
    $a7="6d44a7d2bb55aeb28c4dfbc50074355b037dc92819ca29a200d6602b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}