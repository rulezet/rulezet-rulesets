rule sha512_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0d923ef504d45911b5faf90fe08f8b1ef9fa791f65533cacb98dc8c072e9ab2cd0ff40f340e01b2a816103c1633a70f5d16a2a230c5aa253720bcf94755997"
    $a1="c31ffbfd6d9f25760d7b4f63c1052186d01e5da24aa4d84a02a2a9a6f7bfb82003b04f622bbab6ba671c5c480646741abd46b01e5deaa98e47c07363fd02767f"
    $a2="7fcf4ba391c48784edde599889d6e3f1e47a27db36ecc050cc92f259bfac38afad2c68a1ae804d77075e8fb722503f3eca2b2c1006ee6f6c7b7628cb45fffd1d"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b4953a66e8a7b959fc17858e8bd502919f3c8c68bb7faa5c90cf5a1d9ff464facdfbf4e9bbb23c176932dfae1c2c67ae52f9db05c6d6c4a3f10e78447dbb80e1"
    $a5="40b52f07521541f96687a1bf0fe94c1e23c21e57f4d9dd62cc49ce0922f8f7a4f47d1972c2c29e2ae59313ea799e890ed6389efc5c1992add24321440e4053bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}