rule nthash_hashed_default_creds_zyxel
{
    meta:
        id = "3XJAob48sRQp3DD4a5fcVf"
        fingerprint = "3ddca5d1fda7e25eba28e8b288f7246c5a0b0068e035937239f862d0f5f9e1a9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a4="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a5="3726db814d2c2a76946e80c5d006408e"
    $a6="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="0124f83cd4a99a77a28f189d99ac32f1"
    $a9="f973f7503111e3fd696cd2b026790eac"
    $a10="d144986c6122b1b1654ba39932465528"
    $a11="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a12="209c6174da490caeb422f3fa5a7ae634"
    $a13="209c6174da490caeb422f3fa5a7ae634"
    $a14="ea7c23f2efca850e3fb547ca12567c33"
    $a15="209c6174da490caeb422f3fa5a7ae634"
    $a16="7e671b8678a7519e1a36b83ac8275055"
    $a17="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}