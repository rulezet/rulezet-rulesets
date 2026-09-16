rule sha3_512_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
    $a1="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
    $a2="090f304f4a56d59acbe2103b05204ff370a28c2309ff0dc8223a8e93515d269b5d8096906e2f8424930e957cd0421200a8b52a0080cff0efa14d8d91f8c2dbb6"
    $a3="c91b2b4093bbf2b10d9dc2552da14de9e7dae514b9af39073c4d54f7a25b3e96c85696a4fa54d643ddf3f76b57aeccb06a266d4625f7a3ebaab7a2ec2fcfad5f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}