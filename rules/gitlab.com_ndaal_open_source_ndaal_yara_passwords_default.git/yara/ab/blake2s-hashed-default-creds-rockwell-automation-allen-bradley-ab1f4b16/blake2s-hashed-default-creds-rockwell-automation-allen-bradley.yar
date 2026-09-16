rule blake2s_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="894b385d5c8140943a4cb0d77317f4d892ef5b796b09f06e6b6dbd940fdc4cc3"
    $a5="fff9f2722d6603f74cddf024b6a0bbace26b322689919a5289474a9b6b12c22f"
    $a6="894b385d5c8140943a4cb0d77317f4d892ef5b796b09f06e6b6dbd940fdc4cc3"
    $a7="c7c1e70a09034c28aaf217377ad3370439e6a46ed9e249abe4ede6361aba703f"
    $a8="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a9="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a10="b1dc7bc88bfda20471d760fd627a3cd8b1f4df6d7e625ef41b41b8859d5b01c9"
    $a11="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a12="6dbf890cd626cd2f30cded320fee1c2d9aaa5d1932fceac1dd99b8edcfd8477c"
    $a13="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}