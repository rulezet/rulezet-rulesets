rule blake2b_hashed_default_creds_mcdata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcdata."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="71ba4e39e4601766362a91b5029f2d601f54544f5d8cde253e04971365e3bb190c862fdf03e3b925219ebf4d37b54db669248d175698e5a7c51af9f62ffb17aa"
    $a3="6667900cdb32174bd3dd4f1baa289142d4676081a559e456352025cc82874584040f1ca54fd155c29af149141ee4f76bff29f80b3a1eed06911915ac74f2105c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}