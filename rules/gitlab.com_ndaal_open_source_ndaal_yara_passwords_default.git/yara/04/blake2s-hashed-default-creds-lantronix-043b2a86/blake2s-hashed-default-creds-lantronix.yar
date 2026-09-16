rule blake2s_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a1="73baba47b79bb83663182e7d9bfcdf5e4ce5c7812d7d91995b704d01a29e0b5d"
    $a2="50306d5ff12c751f2aefc09e5b3df58b84a676fbebbb8fd17b84b6a445c6df5d"
    $a3="0eac0ddb08d482a2cb9e297e499508a9e4f4b229229d43a6f2f78d129ebfb203"
    $a4="13ed751afcecd936bcbe496a38545e63d2fb97f2ad8fc5b72f17d29784c34db5"
    $a5="8a4c21160430a7a93bedcfd6876aa77a9269a4ab59aa6adb42692717f6a2bb80"
    $a6="50306d5ff12c751f2aefc09e5b3df58b84a676fbebbb8fd17b84b6a445c6df5d"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}