rule pfc8_31324ac2d96e6912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.31324ac2d96e6912"
    cluster         = "pfc8.31324ac2d96e6912"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeapp adlibrary adpop"
    md5_hashes      = "['923776a18b127b3332e8bafe4b9ab1d679695f76','d434e73a4e465018031df27bffcad0786771ec7b','dd54d21ea71a5b9563d252737627e271cf5b8b76']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.31324ac2d96e6912"

  strings:
    $hex_string = { 96 21 aa 1d 97 41 5a 76 1e 9c 4d b1 94 9d 88 80 44 83 e8 31 29 93 5c b5 c5 0a c2 09 43 b3 cc df 7a a0 74 65 d0 e4 32 01 c9 59 b4 27 49 fc 2d a8 25 0e 58 e6 c7 3d 50 c6 ae 1b fd 18 d6 8e 1f 37 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}