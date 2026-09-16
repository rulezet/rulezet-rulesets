rule sha3_224_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="83c9df742ea0388364c6d0336631d2bb9f88d42d4d121572e452e940"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a7="7a96f4d91945a6fd2a001dc10517a287d1ee569cfdc55f9005e0c21f"
    $a8="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a9="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a10="225dedff3d385fb473af2f34ceed57657b24ee8a23b3107fbf8c4557"
    $a11="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}