rule j2319_029a850dc6220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2319.029a850dc6220b12"
    cluster         = "j2319.029a850dc6220b12"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script exploit blackhole"
    md5_hashes      = "['b1600ec1d86081b9d7b61a31745939528be26cf4','f58190022f78ef8e8008f304b4eb9cc87946f765','1a2f69254cf6349b716e25256f9a8c6fbb2da743']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2319.029a850dc6220b12"

  strings:
    $hex_string = { 75 c0 a7 a4 7b 8f fe 99 8c 00 96 2a ff 43 4b 03 95 27 87 5a f4 b4 67 47 f6 69 18 15 05 db b0 d8 25 59 b5 90 9a ba ac a9 ce 65 85 7a 52 23 78 ac 64 fd 55 37 99 df 6c f9 ae aa d7 52 46 f3 1d 45 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}