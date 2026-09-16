rule blake2b_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbc2d1b60bebdc3750ffd41f5ca1db6f31633596b5576359a80e05d576647da69ba91e97dfeb89d80ade3fa19dc27d9ca231a6b495c090164b5e442149fcf735"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="e57de8c2943a67dfaf798bba2fdc2a64180d0e835ef04a3e5098476a9eeb981236219cee8de114f0b88ac9c28d6479e631e98e27ae88ef23671ce1a82da7467a"
    $a3="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a4="7932a1dafeeb666498a8d55f05c063cf1f789e8fde6fc472eb0058740492d1c8b08fc2138bea6caf7b618b82b685b4d5c77ee2f4b1e3942dddb73408895fe97d"
    $a5="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}