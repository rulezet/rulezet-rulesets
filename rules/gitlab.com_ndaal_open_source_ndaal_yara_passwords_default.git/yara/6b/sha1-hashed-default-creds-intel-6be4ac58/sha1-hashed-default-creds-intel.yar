rule sha1_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80437a44a661d141174209119d54125a59a64b2a"
    $a1="80437a44a661d141174209119d54125a59a64b2a"
    $a2="6ee3c2907b311f04efecd9f7352918a970a4fe0d"
    $a3="6ee3c2907b311f04efecd9f7352918a970a4fe0d"
    $a4="eecddd10d7bd87d3d765bf65504605117c02ea2e"
    $a5="eecddd10d7bd87d3d765bf65504605117c02ea2e"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="2c84d7a4c96c3d76f7b2b21861abb5ec39423f6d"
    $a9="eba082ff45517c06bd365c2fde1fc77cda7a8f6f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}