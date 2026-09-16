rule sha3_224_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10e7a0882a9b9d786c626098121b1456abfa6df5d7fbdf2efd864f7f"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="10e7a0882a9b9d786c626098121b1456abfa6df5d7fbdf2efd864f7f"
    $a3="584206febaa19efc32de0293b59f0427953405f7465ef0536bb42c1c"
    $a4="6757b05b886d0e0d6fbc5fb63436a8109a68aea24996fc99d27c4d2f"
    $a5="e949436b4c6b5b92db66d8b2c70750ebf1f84ca1e7d5cc2c4a6712ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}