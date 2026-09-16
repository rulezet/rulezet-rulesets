rule sha3_256_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9f87b9793b760384efbd91800cb1d6fa03ce1195b065225334981bd3b74d409"
    $a1="30fdc4981c34bdeab92ab8ed80b598f19ffd964f49a2edeb0603d2df2285647c"
    $a2="37c736b8de3c656e78fa400f46627e72ec44e642f99045216fdaca80329ba163"
    $a3="30fdc4981c34bdeab92ab8ed80b598f19ffd964f49a2edeb0603d2df2285647c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}