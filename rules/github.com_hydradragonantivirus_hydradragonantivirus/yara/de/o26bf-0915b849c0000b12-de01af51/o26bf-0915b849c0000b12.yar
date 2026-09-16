rule o26bf_0915b849c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bf.0915b849c0000b12"
    cluster         = "o26bf.0915b849c0000b12"
    cluster_size    = "30"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "temonde malicious kryptik"
    md5_hashes      = "['8efe121ab1ab3f259036392abffa723a943ee6c4','08f3ddaac56c76630f4135ee9262095acff09f57','4bd3da0402e17ebe7b49b0f8e52f2eb72919b7d9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bf.0915b849c0000b12"

  strings:
    $hex_string = "<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->\r\n"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}