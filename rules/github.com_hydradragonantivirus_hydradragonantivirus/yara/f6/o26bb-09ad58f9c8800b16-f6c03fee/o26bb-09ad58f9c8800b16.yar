rule o26bb_09ad58f9c8800b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.09ad58f9c8800b16"
    cluster         = "o26bb.09ad58f9c8800b16"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "decc kryptik malicious"
    md5_hashes      = "['9eec7f062f43ce8b8bd169d60445bea553f4cd06','6df7e0b4fb5ad5ec5bdb92a9b5d4042e0badb3fc','41b6373a93fec2cfdda5c2fcee1ac85b0ec7a51e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.09ad58f9c8800b16"

  strings:
    $hex_string = { cb a9 8e ff bf 9e 8e ff ad 92 91 ff ae 95 89 ff b2 a9 a4 fe af b3 b6 f0 89 8a 8a 9c 50 4f 4c 13 00 00 00 00 45 b8 46 63 48 d2 1e ff 40 97 70 f0 22 14 fc f3 2c 27 ed ff 00 1c fd ff 2a 30 e2 60 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}