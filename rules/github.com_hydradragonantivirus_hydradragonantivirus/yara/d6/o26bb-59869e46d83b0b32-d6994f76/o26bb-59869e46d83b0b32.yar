rule o26bb_59869e46d83b0b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.59869e46d83b0b32"
    cluster         = "o26bb.59869e46d83b0b32"
    cluster_size    = "49"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "safebytes malicious attribute"
    md5_hashes      = "['09cce201fb57ea93464ef4520a9e28fb853bc31e','a6d590adc892ea02caad5b33a5f7357bb14918e7','60c38df14f580dbd54e8573957beb46bb6c026b3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.59869e46d83b0b32"

  strings:
    $hex_string = { c3 e9 e4 95 f4 ff eb d8 5f 5e 5b 8b e5 5d c2 04 00 00 d8 53 32 b0 20 77 68 4b b1 0a e3 e7 9b 91 ec d3 17 5f 39 d0 aa 52 15 45 93 a5 5b 29 2f 03 aa 7b 05 27 8c e8 5a 7c 66 4e 9b 81 44 7d 05 d5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}