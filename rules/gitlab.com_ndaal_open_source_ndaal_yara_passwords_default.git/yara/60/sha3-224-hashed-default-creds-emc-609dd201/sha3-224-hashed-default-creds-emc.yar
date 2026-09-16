rule sha3_224_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="2c3d933efdd16ae731789df1d9e16ee2fc7f82c146d3492164bd984a"
    $a3="a4c1d857adda5dfc809d113954d97dd83bf14beeec1fe283efa7668e"
    $a4="7ccd52406c65fa2750f2af98b7311f83d4095a1f04e97e979ab80c3b"
    $a5="a1b536ef35e2aca9c8bffe7db3fbbec1ab544343b442f9c207d8deb7"
    $a6="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a7="78f2aea7408e0b140637310f02db6b51f0945e043346db1066c7e93a"
    $a8="cf75acd4f8a6ce88b00c963476b6e898136d3d5d1b007e48b251a25f"
    $a9="b4f65596e7a34b361c97db96506bdbd7b14ad1b16cbd673fdd81a789"
    $a10="e655ba80b0eef8d6875c5d329d9f2ed681240262aa70deb9734573ac"
    $a11="de85fde5226f589ff9d73c1e6e2ce53663c1d30a441725f1f63e3be6"
    $a12="bb6c0932ed44420658738a0194f31e5b9f80c26637cc45efae18181d"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="3580d8fca5a3d7def6d1bbb076d8192b806ba4155c7569c89713d606"
    $a15="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a16="292b5d3b0b5c90e601b72e957c11063331ae6fb53864f25136280cdf"
    $a17="bc0f4fd22fdfbfbeea5edcb2d480fcf1bcb97195f76862f12daa5558"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}