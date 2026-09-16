rule sha256_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="6150912cd17f0a52f820940039abcea92eeb8a1b434324117d04f44459666359"
    $a3="3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5"
    $a4="156cab4396aff1999e21a9b077b7df3ff66c947c4004b37e2bcef1732db038ca"
    $a5="56e2321b61fac819f060801eee7557b3d4f584e383a4511dbba261955b496c8b"
    $a6="342d646aeae5b32172f721ba886314439c64e6a81d287cf744b2fd71e863ce6d"
    $a7="56e2321b61fac819f060801eee7557b3d4f584e383a4511dbba261955b496c8b"
    $a8="b462f38412acf13ea9771139375c4af03699aef7b773f0810b553db88c77d5e5"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="f76043a74ec33b6aefbb289050faf7aa8d482095477397e3e63345125d49f527"
    $a11="c4b97afe643da8e91b649cfabdffe821d270de093e189e264b369c329aa3a82e"
    $a12="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a13="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a14="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a15="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a16="5b1ea208c3d08373c1e554f12331020125ae52b3d01977461eb734ca80d71819"
    $a17="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}