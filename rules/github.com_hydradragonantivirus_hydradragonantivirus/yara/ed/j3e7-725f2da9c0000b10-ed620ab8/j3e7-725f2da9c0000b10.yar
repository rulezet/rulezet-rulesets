rule j3e7_725f2da9c0000b10 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.725f2da9c0000b10"
    cluster      = "j3e7.725f2da9c0000b10"
    cluster_size = "3578"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos skymobi"
    md5_hashes   = "['0000eb8544bc6928d8b9e415d5fd8567','000999a4fcbce5f6df480e3930e468b5','01cab85d0f9754e1768b046f273785c3']"

  strings:
    $hex_string = { 5a 79 a5 3c 40 1a 00 83 01 02 00 00 07 1d 78 2d 5a 4b 3d a2 41 1f 00 66 02 00 00 07 0e 8c 1a 20 00 bb 01 03 00 00 00 07 0e 01 29 0f 01 13 0f 96 96 a5 01 18 0f 78 4b 2e 1c 00 06 00 07 0e 00 0b }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}