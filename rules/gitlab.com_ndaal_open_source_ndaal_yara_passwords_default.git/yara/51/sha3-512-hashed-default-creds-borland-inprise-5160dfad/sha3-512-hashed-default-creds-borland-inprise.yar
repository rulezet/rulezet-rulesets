rule sha3_512_hashed_default_creds_borland_inprise
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland_inprise."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bae826dd03f7c866258d7b93bde4be7ffe42d0039032436fa517abbe03da5babd149068e8a7f3f913a474a5c587ece5b7c005f7ad888b2c68e8651a7d40e518f"
    $a1="3e3ba9708644b3076b80bd3d7a687d3dae422148efb4a02aa7e577bdcba9bb28aaae2332ea3967a43f533ebc13b34062a11aa22eb17ac90e276f1a0a5dbddb17"
condition:
    ($a0 and $a1)
}