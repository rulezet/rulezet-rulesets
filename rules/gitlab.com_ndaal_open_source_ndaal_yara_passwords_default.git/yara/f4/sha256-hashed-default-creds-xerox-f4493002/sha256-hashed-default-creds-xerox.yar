rule sha256_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="efc5b01efd64fe0c823867261b71664d98a0e07e298d10298b41c6cb75f37e5e"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="cc399d73903f06ee694032ab0538f05634ff7e1ce5e8e50ac330a871484f34cf"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="efc5b01efd64fe0c823867261b71664d98a0e07e298d10298b41c6cb75f37e5e"
    $a9="d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2"
    $a10="0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="133006b874688f82232b7520a582ca1cae8c6587df2a959ed0bc738078a71d77"
    $a13="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a14="bc86e3cd94a18e6232a48e2e6ae7ebdb30232e2859935f3c6acfa5fb90c31636"
    $a15="00197d6aaa1b2e6203523e21311fb4825149f9cb404f54605eb974e8a24b95e8"
    $a16="cdb2e0d0f873ce5326e87cf7dec48de8da3043cfc950a7eba05a059150e873f5"
    $a17="644c189710ca0d5f3bfc755fabfbc59899aaa5dcb8331c384d24d35fdc0bdde1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}