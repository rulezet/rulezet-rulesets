rule blake2b_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f63ecf15e5394752b769f5a96edb5f14fd8c5a48cb6a1582556a5db146e82ceff6efd16c5b50f1db3e38a7d2825bc90b67b309908227bc2a7de90059579314ff"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="4b1ef8a2a4246b08c89a7fac3b8f5cd0678cdd982abb4238b9585c8c7864508dad8839324af2951c693baaed1f5afe55e3dbe07d02a05a190dbb81a1c952e58d"
    $a3="91e3de309f10ae1c579417f9607b3d4f2d7910871a5328b162d0dbe82a076b6253f6e88ddb50ab7b4f7e2b133af58a0b7ca522654a0e07ac207862170916556b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}