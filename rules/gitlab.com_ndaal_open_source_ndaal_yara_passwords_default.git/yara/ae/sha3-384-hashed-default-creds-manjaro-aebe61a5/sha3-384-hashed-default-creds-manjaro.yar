rule sha3_384_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0065adbe09bce08fc62d02ff50cb3f1789975949533671a6bfec493bb07d63ab5afdb45f74080fca093fe2dc845fd8a6"
    $a1="59d290af8d204c7538ab53f39b3e2d0516e78ba2613633082fcae36ba581c60f4580e4ec9ccd6692ea6bf81949194c79"
    $a2="f19041445e380ac3a00d6f94c00dce1a2868d7433a24878664084a1a8898ce4a155343a55a3c0452c9ff9df256644534"
    $a3="59d290af8d204c7538ab53f39b3e2d0516e78ba2613633082fcae36ba581c60f4580e4ec9ccd6692ea6bf81949194c79"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}