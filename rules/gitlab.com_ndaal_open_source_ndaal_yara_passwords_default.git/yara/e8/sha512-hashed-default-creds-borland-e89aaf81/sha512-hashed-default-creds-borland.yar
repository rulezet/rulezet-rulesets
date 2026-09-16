rule sha512_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fbebc93b9758faa9d46724d4e2b4de2be95aae02fc51f2013a3e987719039ec5a0d6fd50fa2ce83671db46e7c5d6f2509ea708ef11bc3413a917d935fdc30e7"
    $a1="d2250b03eec37b0a31905b48f96e18fde8c50ecda5aeb2effb782619d7900068c661672367b6a0d7c2a046ce91c45210a851d972c3ba41bd6bea749ca406f39f"
    $a2="3fbebc93b9758faa9d46724d4e2b4de2be95aae02fc51f2013a3e987719039ec5a0d6fd50fa2ce83671db46e7c5d6f2509ea708ef11bc3413a917d935fdc30e7"
    $a3="4f533f805800876727fb2ce5273f3d0400ffc937cf421ded43a84857c978874873cd7b5b9c94f55a92311fd89dd44958155443e5956c322302a62c1ed1e88106"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}