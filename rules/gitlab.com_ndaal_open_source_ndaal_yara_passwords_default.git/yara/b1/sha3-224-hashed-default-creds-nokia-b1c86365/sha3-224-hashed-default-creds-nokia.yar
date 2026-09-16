rule sha3_224_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e08ddc7460d3a0339638ff6a250888b2fdd5279ff8a13c1a8f84bc6a"
    $a1="e08ddc7460d3a0339638ff6a250888b2fdd5279ff8a13c1a8f84bc6a"
    $a2="d20652273bc03d450977787afeeb7b83cb394d78eb3fb1c2237f8e06"
    $a3="d20652273bc03d450977787afeeb7b83cb394d78eb3fb1c2237f8e06"
    $a4="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a5="e4edba7fad7cb671e5fd65394c56bb10d40a3fa809b44f7fdd3725ba"
    $a6="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a7="37788067fed012db40ecbaff604c112684f0685d131bae1649b7ae76"
    $a8="dacf4055fd6f8f8b4af04ba59f7da52b72ae3ac620f8c6bf985e847c"
    $a9="37788067fed012db40ecbaff604c112684f0685d131bae1649b7ae76"
    $a10="55511238d0d82eba3d5e323fe3d0f4c6dbae811f3ba28e136ce6063a"
    $a11="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a12="30026b68fe664d44c650bc4445adb5806fcfe8129a77b32112cab8d0"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a15="ad89019dde61894842a61f2f2272182a68e1b5000ba353aa9e3e9205"
    $a16="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
    $a17="20048b1f2fe61f29a4e1b33f4ffcf2fe777005ef616ac5a0e48e110b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}