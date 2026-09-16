rule sha512_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a1="cd714d8864b22e5b5e0f05576843058225ee4303c3bb3b34234333f88fb4d136d93a58ecdceefd78246736cbbc35152051104e9f0397e4cc8de7b7582231fa15"
    $a2="07a31c3f230c522b53af20859631a510635ec7e75e107f29298d5f05a988a4c7905d06edfa155ae57162a72fd7cf7ac9c1dffa658a18e8529ece6d3efb0fb05a"
    $a3="07a31c3f230c522b53af20859631a510635ec7e75e107f29298d5f05a988a4c7905d06edfa155ae57162a72fd7cf7ac9c1dffa658a18e8529ece6d3efb0fb05a"
    $a4="5a738c9b375511f3219c3b866b10a3aa787dd69d259d756926b5fe6d6ced540cb6671db78b429b14542f89616367c3a4b553c28249ddbf7a5a283dd8db4399aa"
    $a5="5a738c9b375511f3219c3b866b10a3aa787dd69d259d756926b5fe6d6ced540cb6671db78b429b14542f89616367c3a4b553c28249ddbf7a5a283dd8db4399aa"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="a5d335fa30ced7505dba4e2c87196c752dc9c6395b03fdfa1097378ede971ce78a0ee4709b75a2a625b74da29952fc01997ac61d619b29216330030094011b69"
    $a9="6d9aceb1053bed5fca83b3fe6bdbb38389f2d952631668e2447615dd1e3100f49445060216879540f96e99b444715e0e2b84075e2dec6d2720c81acd3551676c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}