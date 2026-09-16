rule sha3_224_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47a38f4b5bc88d3c6839ad535b801aae8873cb10720d59beb0689664"
    $a1="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a2="0804a519bda432cc382df7ca38d5ca53377597e4f3d5625c5a0269a0"
    $a3="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}