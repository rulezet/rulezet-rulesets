rule n414_53354a4a96a31912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n414.53354a4a96a31912"
    cluster         = "n414.53354a4a96a31912"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy dangerousobject malicious"
    md5_hashes      = "['a15d50e55bf868404128bf042e9edfa16ae99922','9ee83ede6f45897d774f6748e2482a56759d34e7','a7effafa88cc4945799c961ef3b5c8ed626cf651']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n414.53354a4a96a31912"

  strings:
    $hex_string = { 8d 90 29 31 77 81 06 89 0f 2b df 14 12 27 0d 71 1f 51 21 de 5b 1c 38 b2 a7 fe 61 19 bf de aa 3b 0c 98 28 22 36 3e 47 8c f7 44 cc 74 f1 0e 84 70 d6 c5 9e 83 d1 ce 57 9a 05 09 91 94 82 e6 bb a1 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}