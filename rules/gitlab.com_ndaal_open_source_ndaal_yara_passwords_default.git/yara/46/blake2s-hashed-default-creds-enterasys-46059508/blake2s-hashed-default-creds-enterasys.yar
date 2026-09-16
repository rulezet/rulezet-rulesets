rule blake2s_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f292b71f87f3b514e1d443926f047d06569387a14ab0934f660a3c38b1a758d0"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="03cc6210c5b87903186f0be376407a1933d9caa59043e249a1921870ad9d3dc9"
    $a3="f7262995c54e4c2dad3fb559926ae798ef3f5df56b4ecd769bd577491ad89a59"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}