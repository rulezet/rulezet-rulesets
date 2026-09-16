rule k26d7_01b1319ab65d2b96 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d7.01b1319ab65d2b96"
    cluster         = "k26d7.01b1319ab65d2b96"
    cluster_size    = "253"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "somoto betterinstaller malicious"
    md5_hashes      = "['fe3585e249b7bba799d87f7ef05b679b73b474d3','01b92f9626026d404cd3ddacdb52869df2ded920','0b838b41b4790030bb6c3cb4cb33cc5a34e71c3c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d7.01b1319ab65d2b96"

  strings:
    $hex_string = { c3 04 8a 03 84 c0 74 1a 66 81 3b 5c 5c 74 10 83 c8 20 83 e8 61 3c 19 77 09 80 7b 01 3a 75 03 83 c3 02 89 df 89 de eb 57 3c 1f 76 45 52 0f be c0 52 50 68 dc a3 40 00 e8 0b ff ff ff 5a 59 80 38 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}