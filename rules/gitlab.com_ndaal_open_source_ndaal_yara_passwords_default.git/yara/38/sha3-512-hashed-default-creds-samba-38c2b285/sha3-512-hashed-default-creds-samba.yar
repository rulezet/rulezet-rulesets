rule sha3_512_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f28ebf2dd4962b4cdac27b3156c47853669d9acbf5727bb156a090fb1520d6e685e9356cc2d6b53361bfb885f18727d31596cf2052c139626ffd5299b3d2e0b8"
    $a1="f28ebf2dd4962b4cdac27b3156c47853669d9acbf5727bb156a090fb1520d6e685e9356cc2d6b53361bfb885f18727d31596cf2052c139626ffd5299b3d2e0b8"
condition:
    ($a0 and $a1)
}