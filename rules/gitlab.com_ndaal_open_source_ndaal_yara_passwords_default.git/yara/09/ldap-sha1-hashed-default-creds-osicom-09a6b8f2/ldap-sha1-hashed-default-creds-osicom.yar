rule ldap_sha1_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}/GeDs8q9TAmsen2oRSn3g8DhHrI="
    $a1="{SHA}/GeDs8q9TAmsen2oRSn3g8DhHrI="
    $a2="{SHA}VQiTNN2ceANTf3NR6muaEad0Mvk="
    $a3="{SHA}MvquysdCEA93U/DB0KoK3QG0BGs="
    $a4="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a5="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a6="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a7="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a8="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a9="{SHA}VQiTNN2ceANTf3NR6muaEad0Mvk="
    $a10="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a11="{SHA}stIedx2fhoZcXv8ZNmNXTdF5bI8="
    $a12="{SHA}n4ojiaIMoHUqqelQk1FVF+kOGUw="
    $a13="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a14="{SHA}Tnr+vPuuAAsix8heVWD4mioCgLQ="
    $a15="{SHA}/GeDs8q9TAmsen2oRSn3g8DhHrI="
    $a16="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a17="{SHA}ur4wUOLoHf2HqM5nJk1RjLNK73I="
    $a18="{SHA}stIedx2fhoZcXv8ZNmNXTdF5bI8="
    $a19="{SHA}stIedx2fhoZcXv8ZNmNXTdF5bI8="
    $a20="{SHA}w5nmWwCqiwr946izWsyUfYKEYFc="
    $a21="{SHA}eEH7H5K5kZTKgY1BDLCUMHMbYoU="
    $a22="{SHA}6AcheTwkrhTt/KmyatQGqYFc0/8="
    $a23="{SHA}4dDGwcKeatUWQHKlshNA3Kf8sFI="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}