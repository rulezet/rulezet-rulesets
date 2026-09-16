rule sha3_256_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc3e3e7aae8ce30b86a5da56d6460f90d605bef2e2068ee7c50f8000e8b56192"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="f524b7833a9d4b3e4cc158d1be005c1a18cfadc03bae6af38a0bdaeac9c29f31"
    $a3="06ef834cd3b080074a694d172db0bb0ebfd2f3bac5d943a1e8f97ef17b847853"
    $a4="017383d51ba86830b8bc9864b8531bac6449ef36a0dea9b9d8bf471bb4366c8b"
    $a5="ac2247a99c3e17aac292908eb9f36780b469c57c5fbb916c6b91ec0d13888346"
    $a6="e2025ff4d76d05c3f8fbdb1bba8e93ec67e7a726e86fe4783f3dc2eada17d3b7"
    $a7="a91b5c25b6af4afe0d19dde9bb501bc4d099b09f34d035b51fc4c2d7733bfb51"
    $a8="fec3572a226527ba9a636836222a7231362a9f348b1a4caf2cbfef230a703aea"
    $a9="ee372019b48bff763cdab6b666d63d413b6bab26429d03f66406dbef07b978d8"
    $a10="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
    $a11="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
    $a12="79c2d64847da284b332e5fccd1282acac0290528ee4d63f398c15e64d031e478"
    $a13="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}