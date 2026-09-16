rule sha1_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a1="b86c9d332f80d68ae3c274c984219fbb999ab5ef"
    $a2="4ffdd4db4eb1bd5865a8d3b7a9cdbfb587465df7"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="ece362775003aa2cc452ed00d3c1fa5e0f7bf77a"
    $a7="8f198fad85c1ade2c1fa575158726672d789eeea"
    $a8="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="cf21d8584300263ad59d8153217c2fe3e87ff2fd"
    $a11="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a12="bd71c71b4ea02571c9fe058b7e9b2aa2ea2ccca9"
    $a13="0287e6f69b8d608a1e4e4582519f4154d1a04408"
    $a14="f58f1c9bbbced2419818a0a2151e340adcc0cc8b"
    $a15="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a16="5f5020d67d0b633e59f81c0a9353fc67f328b0de"
    $a17="7505d64a54e061b7acd54ccd58b49dc43500b635"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}