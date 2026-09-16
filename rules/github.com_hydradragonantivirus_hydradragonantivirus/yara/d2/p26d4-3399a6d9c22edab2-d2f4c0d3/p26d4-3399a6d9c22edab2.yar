rule p26d4_3399a6d9c22edab2 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26d4.3399a6d9c22edab2"
    cluster         = "p26d4.3399a6d9c22edab2"
    cluster_size    = "74"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "wajam malicious riskware"
    md5_hashes      = "['3580bcab6bd6aea27a6c857a9911f099e8062558','4e4e27c6755e6963348e9b544e364fccd58e3084','3a67e61951546a56a10097ae27213775b37f9278']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26d4.3399a6d9c22edab2"

  strings:
    $hex_string = { 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 30 31 32 33 34 35 36 37 38 39 5f }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}