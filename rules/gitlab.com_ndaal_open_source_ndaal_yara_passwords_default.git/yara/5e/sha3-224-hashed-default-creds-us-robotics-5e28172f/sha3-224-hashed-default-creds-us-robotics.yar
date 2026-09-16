rule sha3_224_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="6e1ff225333ba37a13cbdb7ef72b8975a5e2e296698c06ea0fe65091"
    $a5="6e1ff225333ba37a13cbdb7ef72b8975a5e2e296698c06ea0fe65091"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a9="a7958fb4bf861c0de89ee4fbc7e08e6a85679ea81cbd8de2181703ad"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}