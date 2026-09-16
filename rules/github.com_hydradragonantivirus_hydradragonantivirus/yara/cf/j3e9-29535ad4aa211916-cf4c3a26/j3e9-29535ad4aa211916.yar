rule j3e9_29535ad4aa211916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.29535ad4aa211916"
    cluster      = "j3e9.29535ad4aa211916"
    cluster_size = "3225"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "delf fileinfector hmjfa"
    md5_hashes   = "['002015dcb08a258baba34c25ec3c1c19','0029f94fb6a49d33b2a4d7ba883015e3','019c997cde4ab21891d1ec7def2f34ca']"

  strings:
    $hex_string = { d7 b4 92 23 e4 ed 1f 7c ea 53 06 3c f2 a8 66 4c 51 1a fc 67 c6 03 ca c7 04 24 cb 7e e6 a4 95 d6 78 bc 17 48 6f 26 8b 00 f7 02 94 75 2c 09 d2 40 c3 1d 4a cc 7d 22 49 50 81 2d 5f c0 30 dd a7 f8 }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}