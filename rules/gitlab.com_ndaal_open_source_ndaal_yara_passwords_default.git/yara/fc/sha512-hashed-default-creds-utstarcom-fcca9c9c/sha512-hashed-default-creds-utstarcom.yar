rule sha512_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4476d0f368617d2d798387a92268c2af27e669c5f7f05439ecdbae8e8524bda8164f031e444c113393e22a80b516b848aaae23c972f32adb57963492461302b"
    $a1="a4476d0f368617d2d798387a92268c2af27e669c5f7f05439ecdbae8e8524bda8164f031e444c113393e22a80b516b848aaae23c972f32adb57963492461302b"
    $a2="a757a064f21d0a91a35bb63c9eeaa208a48079e9e21079e1475954504ad3bdb69554f06f51a59da9607d91b867d308eb560e494d8506819c5e22688cda839f5b"
    $a3="061f982a2f8e4377539b82a36dbfbf716cadee5742a8d665ff066192456c47f094d4c5bb9a75acd31eda62ecac5d3b96f768480bd345fd628f585f1b3ab74383"
    $a4="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a5="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a6="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
    $a7="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}