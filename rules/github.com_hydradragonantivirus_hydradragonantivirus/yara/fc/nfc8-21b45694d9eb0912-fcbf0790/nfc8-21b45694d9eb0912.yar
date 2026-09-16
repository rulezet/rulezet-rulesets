rule nfc8_21b45694d9eb0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.21b45694d9eb0912"
    cluster         = "nfc8.21b45694d9eb0912"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "podec fobus mkero"
    md5_hashes      = "['ab2c33eaa5396d5448ce1ac6cd5668a1837f0a61','c6867d6a65fd75ae6e88d76a756b6b5403d89748','a3fb56f1bc62f2eff851e31b03d39bfc6f5e3a24']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.21b45694d9eb0912"

  strings:
    $hex_string = { 27 eb 5c 57 0a d9 e6 d1 17 8f 9d 23 9e fe 0c fc 0c 4f de 7d 0b b1 75 a8 8e 39 36 ce e1 49 41 ff 48 11 e9 05 ab 3c ad a9 06 76 1c 3e 5d 3d 67 be c3 ae 91 72 d7 74 8b 30 32 14 f2 1e af b9 61 1b }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}