rule nfc8_5acacec5ea211112 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.5acacec5ea211112"
    cluster         = "nfc8.5acacec5ea211112"
    cluster_size    = "197"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos fakeinst hiddenads"
    md5_hashes      = "['1c75bd49beb22a5d1368fd66b217f98aa0f982f7','0bb6f3c65392773bbc499f034085372f70a5b4c0','f520c309dc66d87c95adf8a88627e18156835514']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.5acacec5ea211112"

  strings:
    $hex_string = { 0e 00 23 04 34 04 30 04 3b 04 38 04 42 04 4c 04 20 00 37 04 30 04 3f 04 40 04 3e 04 41 04 00 00 0c 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 71 00 75 00 65 00 72 00 79 00 00 00 10 00 1f 04 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}