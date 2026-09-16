rule blake2s_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf666e156f39296a510f114fb17990c04523762cfd8d1a036a34ab96608cdbe4"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="cf666e156f39296a510f114fb17990c04523762cfd8d1a036a34ab96608cdbe4"
    $a3="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a4="d088bd7ef99232e4eecbc1b4966ce016af08ab217fad21567a3c19d9a27aff4d"
    $a5="d7f8339d68259de3f434ba48805e31a95dc469f26dc7d04f6f99aba404be49ee"
    $a6="cf666e156f39296a510f114fb17990c04523762cfd8d1a036a34ab96608cdbe4"
    $a7="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}