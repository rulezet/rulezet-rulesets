rule sha3_512_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f20eff79db19db192a4f49b8e6a4105903cf28a204a4195625a1875eefff4163b3902dd35ececf2ba52f9a9a2e43f8dd575b393fae0792499744172ef450d28"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="62208c35c26c71b4729b39815db5e63e23afadab876bd011cba8c2cb5de61bda14d2460dffc70a9f57248ac1a5630f1039ff3d0e28b1164423eac09186104783"
    $a3="8341d8275dc4d8280ada002618edfce79b33ac25b74394c918168ede320423cfbc8f42f581aedcde002cea5d4f14dce3d19d593edf2c9811c905d5647ab6a230"
    $a4="591cfba5427daacd099b5c300497333c7e518b603d78e27dded50c9077eb1e500dfd62735b57cb580b46c3bbdc9b5c62f2f7378b0322faa43a89dcd2748ddde3"
    $a5="eae47ae73e3ef92a86147c5a643381f9143d360d22d83b6f8983e86a1adf7ea3ef4c0cd5136627e10593b590e5068ada1e6d11d43097182310611a001c842aa5"
    $a6="d1edd3baf4879cd6da2ec415064a357aaa93eb6e5272cac36d4e3686a2e4e7809640b9fc57c17dcc10cf645b5c05d6d1be0fac4c13c443608e1b68d2f5ca2310"
    $a7="a46eed8f55b756dcfa477cb621209ecc170bfa1c4fa1b3cbe4437003ab0b883cc93f2265ef79b952e30058671477a862a37228759e3259de1119bcc44a19b74c"
    $a8="6fc99f5ae5ba7605fd6ae2d3d2b5c56821ffb0a9e1f257ed31eaee5bc374919bd8aa81fdb7ab9cfae9d0a7de7cd98f2ec45c5fa9998eb04ddfdc01e754f6411a"
    $a9="cb3b953d592297d5ca7659f59e3c0dc1c7a273b851446855dd90854e14606e96b355d9b419766493a56cd06e28d6bf49849bf33951787d00af188f2663e18df8"
    $a10="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
    $a11="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
    $a12="973a19d88dc29aecbaec2f40535e3b6ab3d22354453a554cb3c58089830e23cdd803497c8c21519e4f53a35a3f3bd7fd162983586e9f5fcc55124ef31aa437dc"
    $a13="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}