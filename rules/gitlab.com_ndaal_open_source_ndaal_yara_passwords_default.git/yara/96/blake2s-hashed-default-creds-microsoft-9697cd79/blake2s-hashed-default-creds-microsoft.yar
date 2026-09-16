rule blake2s_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a1="36823053efd5881af427a85643737eb92ce445de6dcb24fe04d4478d1687387f"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a5="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a6="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a7="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a8="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a9="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a10="2e165bc4791c525b47a7e8df1a45ef56530cded9097fb532c464204c7ed1ef9b"
    $a11="2e165bc4791c525b47a7e8df1a45ef56530cded9097fb532c464204c7ed1ef9b"
    $a12="03c74c30e1bf2e1dea38c9dfebc00cdfd95006e79b56e209adc951f0e9fc9b5f"
    $a13="cae9c5f376efeb3dd5890f146db55c4cb6c4a3779cce7ff9f4ba4e78881f14d1"
    $a14="257c4331c9533c5caece6e4705ba2215ee64029fe71e471736b1337197498d8b"
    $a15="257c4331c9533c5caece6e4705ba2215ee64029fe71e471736b1337197498d8b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}