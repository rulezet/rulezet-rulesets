rule nthash_hashed_default_creds_mitel_networks
{
    meta:
        id = "6PIp5pXmP9rS1st6wTdVp4"
        fingerprint = "f51348d922872b44f8f8320681955dbb86a2314529c4d0a43406b9c9c2c6df6f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e52caf2cd5f6c0058af92938b853cca"
    $a1="97090730e7e25e0cf351ef7b99f7b56f"
    $a2="789050b591b971e873741eb1ee7559b3"
    $a3="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a4="789050b591b971e873741eb1ee7559b3"
    $a5="6b57d6553205fa3ac14cfddf9ae1c9ec"
    $a6="789050b591b971e873741eb1ee7559b3"
    $a7="b59db4ed6513e7d35fc18e744036bd8d"
    $a8="2e52caf2cd5f6c0058af92938b853cca"
    $a9="29ed6043f57810b5f405916c1c5ac2e4"
    $a10="789050b591b971e873741eb1ee7559b3"
    $a11="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}