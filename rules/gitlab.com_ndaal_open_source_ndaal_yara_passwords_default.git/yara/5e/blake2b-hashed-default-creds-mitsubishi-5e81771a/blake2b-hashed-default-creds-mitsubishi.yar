rule blake2b_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65ef365534689612114bfa85545d52af56b013429efe83b2edda7e32544463d97b01c0ebe680f6f6d4993bacef22c243e1d4ffb4cbfd513a61fe450ec2d6e2fc"
    $a1="65ef365534689612114bfa85545d52af56b013429efe83b2edda7e32544463d97b01c0ebe680f6f6d4993bacef22c243e1d4ffb4cbfd513a61fe450ec2d6e2fc"
    $a2="765dcea4b5abea439c5fe9cb6b8ecde3019a3f4c441953189f9a87090291b195d049f83cf0eaa8e34b924ec518b89589f72a2b2fcbdb1393757c74e6d1552103"
    $a3="765dcea4b5abea439c5fe9cb6b8ecde3019a3f4c441953189f9a87090291b195d049f83cf0eaa8e34b924ec518b89589f72a2b2fcbdb1393757c74e6d1552103"
    $a4="dc26455eebc5a142bd2299041811bf16fc1c902374a0db57a919ac4d0d0f6a22226c4743bc866a9eb53cfafe816e3289ce8380c1bcbde05f9e79d84abbd926d3"
    $a5="97e8a7ec7be2ee207348d4be4772561844f8bea34dac6fe6b390d055a3254edbadc42335720d203b3a7cc69c7fc09981653bd5b437f0556189c182c03bb10f89"
    $a6="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a7="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}