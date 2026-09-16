rule sha3_256_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c4a692062672455af883825e9a689b94e91bd13116b9a7d732620e4752eff82"
    $a1="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a2="d0005fa4a909d9c74dbc2a081a5ff45873448731191ce58f28276bad8cf0e524"
    $a3="1a22edd2d67f9a1d30f5d0cd841bd89da3ac7c2e3c6222de727cc5e71a690629"
    $a4="d0005fa4a909d9c74dbc2a081a5ff45873448731191ce58f28276bad8cf0e524"
    $a5="bd4164a0e5e807d15a54087ec2ecb5472332bf4b906fd38bdf003f47a80d26ec"
    $a6="7e5c4ebec5420ea402ba8852589b32600272133f8fd417bc7d2e80afb87d9945"
    $a7="48e2cdeddf65361fce7c46d45f601da5a9cfbbee7a4481a803fb69ae41d0d049"
    $a8="ed15e9a9e067e35a498c0eb101828c41b8f006e616d8ec4fff6ce6fe711deec1"
    $a9="ed15e9a9e067e35a498c0eb101828c41b8f006e616d8ec4fff6ce6fe711deec1"
    $a10="61137f36b4d307be286ae43f5bac090e280e3a1fabef1515e102479c90125b52"
    $a11="0d1710652d53d8fe368f121c2024d013df81927c576411f2b895f763ae951d61"
    $a12="31e2667321aac1c32078772ce0cd450c192a07e82f9fbf86845be34af261a365"
    $a13="31e2667321aac1c32078772ce0cd450c192a07e82f9fbf86845be34af261a365"
    $a14="7e5c1765ec7a0273b580973d95ff2eb72f11141a1870a2b6d18c3b73a59d0fd4"
    $a15="44d71ba52326358323263aa6c0a17672d44c846ea2aadc296b7d0190f46a441d"
    $a16="2d7c82ec02ede80acbf8171b965439c45c5dc8a2e4a3f9eac24425c4579429ba"
    $a17="2d7c82ec02ede80acbf8171b965439c45c5dc8a2e4a3f9eac24425c4579429ba"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}