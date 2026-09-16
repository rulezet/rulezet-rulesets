rule o26bb_6adb3a41c8000b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.6adb3a41c8000b16"
    cluster         = "o26bb.6adb3a41c8000b16"
    cluster_size    = "679"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cerbu malicious advgoempq"
    md5_hashes      = "['f4f496604c9531dd90e77cddb4ba1397219badcf','66be3a9ee363edd370771edb2dac845fedb9f084','a2b5a7f0833723f50b9aa659997392423382f69e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.6adb3a41c8000b16"

  strings:
    $hex_string = { c9 74 05 89 51 10 eb 03 89 57 38 39 47 3c 75 08 85 d2 0f 45 ca 89 4f 3c 5f 5e 5b 8b e5 5d c3 cc cc cc 55 8b ec 83 ec 08 53 56 57 8b f9 8d 5a 1f 89 7d fc 83 e3 e0 8d 77 04 56 ff 15 7c e0 43 00 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}