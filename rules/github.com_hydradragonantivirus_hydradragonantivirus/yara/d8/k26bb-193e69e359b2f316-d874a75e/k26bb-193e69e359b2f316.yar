rule k26bb_193e69e359b2f316 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.193e69e359b2f316"
    cluster         = "k26bb.193e69e359b2f316"
    cluster_size    = "203"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore dealply malicious"
    md5_hashes      = "['8ed8401caaad49cc05a0ab346172b69c62406655','dcf45dfdecbcb6b158a77e35165bdca649536668','60267a08a21c3f0c73981926afc45a12071bba1f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.193e69e359b2f316"

  strings:
    $hex_string = { 03 80 eb 20 8a 7f ff 80 ff 61 72 08 80 ff 7a 77 03 80 ef 20 38 fb 74 d8 0f b6 c3 0f b6 d7 29 d0 5b 5f 5e c3 90 83 c4 f8 6a 00 89 44 24 04 c6 44 24 08 00 8d 4c 24 04 8b c2 ba c0 4c 40 00 e8 f6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}