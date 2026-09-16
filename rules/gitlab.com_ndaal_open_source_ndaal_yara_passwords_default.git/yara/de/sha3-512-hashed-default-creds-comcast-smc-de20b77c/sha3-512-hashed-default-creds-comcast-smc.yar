rule sha3_512_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e94e157726d1fe780cc7ccfa21937152e6339d93386e3425afa5471afb29a36ff0e7c41bdd87fe0f0ca090c1ab61d2727c5934d60bf5d03e86bbf91ac19a28e"
    $a1="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
    $a2="92412f3f01247436f1201394d18e7ad4ed5d4e378f50e01a0604051924a9470882b53f8cd3818e0d736a2a013d7dd4099c3ee8bcd8b38c3f9c796fe4a915589f"
    $a3="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}