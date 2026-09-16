rule sha3_224_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48879ba9304d8855cbbe8c5ce111e0f504112803bb35a78c870d162e"
    $a1="394f968ef0d4e367a2a1159f395add1f2d6a71a3b257787e0991c2d6"
    $a2="48879ba9304d8855cbbe8c5ce111e0f504112803bb35a78c870d162e"
    $a3="aa7e91ddd91706f6a638e843a9da0a33142ae064e7c77e7bb7221a11"
    $a4="48879ba9304d8855cbbe8c5ce111e0f504112803bb35a78c870d162e"
    $a5="35515d8ea1e270b7743a966efa155c424b1d0a97a0cae07305d9aeab"
    $a6="d8eaa941480d41fe4fe825d721876ff441c801d99e532293b58500c3"
    $a7="aa5f36002e489d9e5afb85761f57c6d6948f48f6ee81b1811e11f28b"
    $a8="c45e6d4a6530ff3706cbb89d6decf95215bfd7387ef5d1bc0705b379"
    $a9="c45e6d4a6530ff3706cbb89d6decf95215bfd7387ef5d1bc0705b379"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}