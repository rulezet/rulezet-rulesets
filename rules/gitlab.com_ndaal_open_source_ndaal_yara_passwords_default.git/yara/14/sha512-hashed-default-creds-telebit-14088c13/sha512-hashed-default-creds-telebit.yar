rule sha512_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a1="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a2="877a07cf4b7e1301aba8a5ce13caa61d06f4c2d3954f235c952797b44cccbc509e02a1c0482489ba76ec5ded767b1b010d34f05fc27f2fda115a35a9c023bbf3"
    $a3="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
    $a4="773080f9e04346d4f0e9d746fd2b04beb1bb9491894eafd580f9e932bbaa59de4311d953a608290045ce3c0ed9185f09502f4dbb999ca045113460a2aa78495b"
    $a5="1baad5fbab2d620deec1b4abf254e871c1112c3909b89fe299a49a1b8b2531c99468e20eca5b3dd26c136743247570dbab7f817f78b614d47687c22b84a7c43d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}