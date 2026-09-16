rule sha384_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cec6d8db288f655e818e6642c913d4f6182fb1a2ec4dcdbbf3baeeaae6814074a5f5b2e7841a2136226be78ec7d39f81"
    $a1="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a2="fe3bf047812714179c282fe1ab57b674dd3c6fdf53b21e98fda3e3fb80d82f1bf0c9afe68f709c9995a9e963ee222dfa"
    $a3="287b08215a74112b4f95497b2b5e3eeb5e1dbf3450fc2734512f69072ff0e4122672fd93edcf71abb68eb2c058a1d97d"
    $a4="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a5="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a6="ec5320f37098993e1881aa925836966302ae51c5f3bc44544371567f5c7650b59f700e2da36e69760cd9a3dd0af6f543"
    $a7="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}