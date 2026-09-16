rule sha224_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="7703ba74becbd034d28d798f7eb86d923f844431b1a827dc4835ab49"
    $a2="93348fbb6bb798810ebe4362688b6f321e6e2ae06031d270ab70a6cc"
    $a3="7703ba74becbd034d28d798f7eb86d923f844431b1a827dc4835ab49"
    $a4="721210c1daf915694b3b50efe7c47b08317eed22d889bd54b6bfb533"
    $a5="7703ba74becbd034d28d798f7eb86d923f844431b1a827dc4835ab49"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}