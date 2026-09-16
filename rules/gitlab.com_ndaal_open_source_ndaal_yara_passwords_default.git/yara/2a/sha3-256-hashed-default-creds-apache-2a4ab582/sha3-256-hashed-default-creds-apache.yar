rule sha3_256_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4dc8b05b12cd3c49153ec4ab9f8181be5320719e24e2e8f15ef90d3a9912221b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a7="78a5fe483b9c1de67f7342ce57fb58e17ce69c949d8ff857e2cc531c323d61bc"
    $a8="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a9="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a10="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a11="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a12="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="df6c9c0063d293b2b582b84e6f3c993a4cc358f6cf049d06ec19e00a95059690"
    $a15="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a16="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a17="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a18="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a19="cc46ba5c3e77e1b482801597d5d672d8e2e7bb01228c8faa44110b3d6189aac1"
    $a20="85aee8bedf1098a3f4b1a92ea65824982e362fff3411d4505dba8dc43fa4274a"
    $a21="dac10a69404388ad62ac4485b200db1e14d043e7a8d2c128ae69c2c1de068f5b"
    $a22="4cfc76b600f6959e2a215fc5c54330e22f698050841e21b90c4088ca30f164f0"
    $a23="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}