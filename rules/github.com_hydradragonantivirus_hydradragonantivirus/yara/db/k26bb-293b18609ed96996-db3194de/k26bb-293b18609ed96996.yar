rule k26bb_293b18609ed96996 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.293b18609ed96996"
    cluster         = "k26bb.293b18609ed96996"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore alphaeon malicious"
    md5_hashes      = "['f54bdfb797c82ccc1114b759ce750fb2c2004edd','3eb363a835d433a245401e37c00caa8e35688df0','4794d8d798d648ed60a776646a1e8ae079f8d131']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.293b18609ed96996"

  strings:
    $hex_string = { 5d 6b 65 20 ab e9 5c d3 f5 6e b5 ad e3 04 dd 23 09 40 61 ae 2a d2 39 cf bc ec 23 7f 92 18 e2 a1 a3 c9 0b fb 98 d6 3b 0e a6 91 cc 71 55 ee 87 7e 77 81 eb 42 1d 70 db b6 22 f6 a8 60 0d 43 88 41 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}