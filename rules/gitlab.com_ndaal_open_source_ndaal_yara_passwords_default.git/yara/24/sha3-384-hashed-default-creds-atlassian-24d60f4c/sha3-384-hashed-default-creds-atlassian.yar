rule sha3_384_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="e045c6bddd0cc3c6cf894ee706ea7f5af2e77f37a61fd98f8cd5e12aa0a00161dd595f3e8fbe48c6be437a30b6148fe8"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="34fffde42c88523308447aa4af6b10f6ef258ab6e15a0a4c364fcb40b1f980febdf801a72ccd980fd2669ad4f40396be"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="9e0407173e24b9c7b4f0137ffa93f405f8b38d6ef86853a5b28d35ae0e7b07c685512cfb17521591d9ec43b3c9c16e87"
    $a6="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a7="74f4f7f06d611aa589d314f00862805a1fd0aacd6570abf369f3b4530356f0944c06c45e7d1f72b3aa0a603baae0488c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}