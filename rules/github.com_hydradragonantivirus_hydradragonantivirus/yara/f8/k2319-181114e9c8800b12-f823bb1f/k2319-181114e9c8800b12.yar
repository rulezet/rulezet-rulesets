rule k2319_181114e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.181114e9c8800b12"
    cluster         = "k2319.181114e9c8800b12"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['c4bcc7cf2fdbde814d018ae263fe6f2f1a34b0be','5dd227a36cbdac7fdc7a1904555baec2d957ead0','7f06bb44a8db9811a5b3b07b2998d25f771d5f84']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.181114e9c8800b12"

  strings:
    $hex_string = "14C)?(108.,119):(0x9B,0x2D)))break};var z1A5={'h75':function(Q,e"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}