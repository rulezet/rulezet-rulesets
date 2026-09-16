rule k3e9_0935a42dda52f936 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0935a42dda52f936"
    cluster      = "k3e9.0935a42dda52f936"
    cluster_size = "10"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre wapomi"
    md5_hashes   = "['18493551884f02e5dbb55bab8c9fa32c','1f816618d4cc84643fc339a0f54d1cc6','de8de7eaf60f6d2f99e6fe37aedc22a4']"

  strings:
    $hex_string = { d8 e0 6c b5 11 e7 3b a6 7e 5a 96 8f cf 2e 68 ce 95 dc 20 37 76 fa 36 05 87 6d 8e 44 a4 f3 54 5f 18 21 e8 f8 35 ee e6 f0 34 1e 9b 83 e9 7c d6 3e 6f f4 b7 16 a5 59 ac f1 20 55 80 7b d1 78 01 17 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}