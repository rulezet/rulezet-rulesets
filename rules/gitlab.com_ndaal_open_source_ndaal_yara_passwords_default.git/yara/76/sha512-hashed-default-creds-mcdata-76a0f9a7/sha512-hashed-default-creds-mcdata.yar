rule sha512_hashed_default_creds_mcdata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcdata."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="5f30f9b4b11a1f70012b59371b37f4b59963e1d00f1044bd2950f4fba13227dec71eba4bfbc32e69145eff249b3698d874fbd6e53eb4ca424a300f4217578f2b"
    $a3="8eb2032e42f00bafd8ef9fdb528797d8b20ba300d5fe17379a0ff6fb230bcf4ddd46e39f106e19ad4d9d6a96bccfcc7743139934886de0218eb2f902730f2685"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}