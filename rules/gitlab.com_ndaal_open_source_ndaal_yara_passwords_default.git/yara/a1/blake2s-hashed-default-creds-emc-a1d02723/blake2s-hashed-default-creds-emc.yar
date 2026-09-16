rule blake2s_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="17067af1913eb555b0283e597e251d154b151d88512be8ddef7c6cb750e09499"
    $a3="872f9846489099e98dd539c29063595b1590a7333961746e29054c242d24b482"
    $a4="7aee28225dd16f75dc40bddbb3d9a6f45476dea164dfc0953530f24a5cdc15f9"
    $a5="fd61773db521a571f1db89f81fb6e6c5380237d343a752ab1c7aa8bdf4fca339"
    $a6="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a7="c35cdcf198f234375ea1d04b1ee224c5586963be534fbab5db534a7f4c41e1a6"
    $a8="62ffebfc7d98cc4cfb2ea5eb239ca64209686a0a0ee3ca6ea62a0f8ba8e99004"
    $a9="db8e41d90b60768cb3a8f0e336ceff6e8cd671bfea6f7dd44e4d571fb94d68f9"
    $a10="7dc1fc2f021c639d21a5fa23845b8ad42b4b8e4dc577126a2c822e6edf53ca4e"
    $a11="f56d297ea2d4a133e0eea828167858cc057619c1376c72f5c6b06d11f4be7e3e"
    $a12="950d9a459d063f60b3bb95fb09a0697e91dd4e389b3c95edb7beabd5765898fb"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="3f7eae1ee1e4295ab992391eea5d33a45e869e50fabf367779086eec821b2698"
    $a15="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a16="71b6dccf48c8ffaaaa5e98a6b66d7edeb700618217887720ad4315dda386a3ee"
    $a17="b767b860ca27311c09f830fc93f10568347a163512ab201658abf899984e4c6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}