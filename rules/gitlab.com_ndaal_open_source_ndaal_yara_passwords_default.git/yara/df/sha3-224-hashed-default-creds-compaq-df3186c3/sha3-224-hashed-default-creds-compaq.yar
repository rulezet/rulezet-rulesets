rule sha3_224_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="b5ed524742d7f070924bdf342635a79d8772822246c34a4ba57c6725"
    $a3="49d6970ac9dab9c1a71a09558b7d0f53cab639bf2812f43c3c76755a"
    $a4="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a5="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a6="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a7="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a8="fce6b65ff1f6bdf9a6f0aacd5e7a9dc7644d73363d611da652b343ef"
    $a9="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a10="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a11="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a12="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="30026b68fe664d44c650bc4445adb5806fcfe8129a77b32112cab8d0"
    $a15="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}