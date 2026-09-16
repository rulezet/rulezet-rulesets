rule md5_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce49a4513aaf0215b1edc8bede398c6f"
    $a1="109d75b65da8400c2f3465a1f5feed1d"
    $a2="ecd7aca2c79673d24418735c9b56702e"
    $a3="97384261b8bbf966df16e5ad509922db"
    $a4="ecd7aca2c79673d24418735c9b56702e"
    $a5="3ac8b8c4b68556e521922052f8b049b4"
    $a6="ecd7aca2c79673d24418735c9b56702e"
    $a7="12886ba771ff267d4f21b08faae0fe69"
    $a8="ce49a4513aaf0215b1edc8bede398c6f"
    $a9="adb074cf39191d6f0b221e2218ce2f4b"
    $a10="ecd7aca2c79673d24418735c9b56702e"
    $a11="54b53072540eeeb8f8e9343e71f28176"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}