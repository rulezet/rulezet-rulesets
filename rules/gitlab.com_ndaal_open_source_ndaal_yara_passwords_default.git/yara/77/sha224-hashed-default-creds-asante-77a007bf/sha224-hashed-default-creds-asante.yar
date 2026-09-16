rule sha224_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="619add9516d6a1f35edcf883c286f6c0964c34526ef6e03fd36e8118"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="619add9516d6a1f35edcf883c286f6c0964c34526ef6e03fd36e8118"
    $a3="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
    $a4="f572a21950751b641924847868714c3edefcf610d0f7f39a100db9c9"
    $a5="37b34e490bdb921eb50902ed04613e6bc307035960f145e78a91f914"
    $a6="f572a21950751b641924847868714c3edefcf610d0f7f39a100db9c9"
    $a7="7fd56d3848ec5197aaff4167bdc5b5910e290efb51f5167f9f114411"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}