rule k2319_10159699c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.10159699c2200b12"
    cluster         = "k2319.10159699c2200b12"
    cluster_size    = "94"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['173ed033e37645d5fd31074be4d4185bb4aa9e2d','536c8ae3d74a48a543de90dcdd4079d703059525','ae45f730dd6ed55a5f2700e2c64b528cb6a132b8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.10159699c2200b12"

  strings:
    $hex_string = "E2?(47.90E1,119):(0x119,0x1A7)))break};var o8b3l={'w3l':function"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}