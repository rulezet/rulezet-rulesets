rule sha1_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="7c6a61c68ef8b9b6b061b28c348bc1ed7921cb53"
    $a5="9dcbd1aed153180d96a490ce54f4d135089406d3"
    $a6="40bd001563085fc35165329ea1ff5c5ecbdbbeef"
    $a7="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a8="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a9="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a10="ef4bfd1e6d278f6bc7d4a478f02be2cb9581a0a5"
    $a11="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a12="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a13="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a14="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a15="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a16="3d19cc2979d1a577f9638faf43efc639f3e45aaa"
    $a17="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a18="5f2db4ccf14c861f406e678c4c5eb0e45053f604"
    $a19="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a20="5f2db4ccf14c861f406e678c4c5eb0e45053f604"
    $a21="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a22="2ea68420690fa9444daf83a68c9bbf249a7bed0c"
    $a23="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}