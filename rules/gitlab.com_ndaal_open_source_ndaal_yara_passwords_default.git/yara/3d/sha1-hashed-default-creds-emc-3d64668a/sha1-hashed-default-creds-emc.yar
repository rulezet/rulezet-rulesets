rule sha1_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="292ce2fc23a59e9d288e56ecbc99fde19c85b1ed"
    $a3="715a3985b3974a82de2aa5ee48d707a720c32566"
    $a4="effd2bfcbc0390e4370e0665d9841efa4f18ac59"
    $a5="588d7aa9bba94febd6e4d13251dbe97344c905c4"
    $a6="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a7="d2d710f94b5205d35e9edd0b0d914dc9c9f70ce7"
    $a8="c0b96ebdbd467f482ef6a026836d8beca5f3a0a6"
    $a9="13390d71d32636f65dd16877f63e6e8981be1d57"
    $a10="41754af759783e38491d719cc3f1c1d5edf46e82"
    $a11="24bf4a8026250cea9439365229b5cf51524c87da"
    $a12="e4134c0c1b404db20151cf205b8c16a28b3e14a0"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a15="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a16="a8c50fb6e4882f8b6ae859308e1bf5fb10e897f4"
    $a17="2a175e2232b7485d6d6116bc4bfdcda72d264ba2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}