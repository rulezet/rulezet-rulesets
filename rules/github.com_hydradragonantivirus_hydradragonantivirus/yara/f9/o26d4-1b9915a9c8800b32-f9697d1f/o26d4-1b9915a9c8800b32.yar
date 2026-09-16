rule o26d4_1b9915a9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.1b9915a9c8800b32"
    cluster         = "o26d4.1b9915a9c8800b32"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "symmi neoreklami malicious"
    md5_hashes      = "['b8b62bdd7bfd1dab61327cd63c57eab4031f8305','978ad61385523971650738676464fa7faae29bc0','3b36834236a4095509edcce3ac0c5838ba6705ce']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.1b9915a9c8800b32"

  strings:
    $hex_string = { 44 00 10 5a 04 00 00 ec 44 00 10 65 04 00 00 fc 44 00 10 6b 04 00 00 0c 45 00 10 6c 04 00 00 1c 45 00 10 81 04 00 00 28 45 00 10 01 08 00 00 34 45 00 10 04 08 00 00 bc 1f 00 10 07 08 00 00 40 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}