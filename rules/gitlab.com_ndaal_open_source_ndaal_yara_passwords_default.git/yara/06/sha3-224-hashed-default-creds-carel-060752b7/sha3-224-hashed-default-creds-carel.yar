rule sha3_224_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad645f91952b93bb6c48129a850609559c46e2f25f70ab1efc683da7"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="d38f285df1681a89f9619514a37271a60b04a96c3d96213c1b701a95"
    $a3="2cf101bf0ce335f6cdeb360fcae0e3bc9ebf70286ae2c0a0032d9064"
    $a4="d5b04af892ec5cac5ec02f32e4705d8132b80de1d042ce5b0386b857"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a6="89ed8db6b9f37af1854e9da36f83cc0d70ed069f6d3bc31a1712709b"
    $a7="339a8c57706b2633624e1d190fc548f399276d7dd6a2c5c6e802f162"
    $a8="712b9d695575b896ca57a37f2e0c4b7838fbf50cf1252494aca1cf37"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="ebb8d1bcfb73115fa144afe02f7f639f8b373842669ed84f1b64ea1d"
    $a13="d26bab4e9b50cdc179d2db65e32568eff47c15f45e3770719d5f48b3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}