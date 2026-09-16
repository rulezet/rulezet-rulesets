rule j2321_231e5286cc1b0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.231e5286cc1b0b32"
    cluster      = "j2321.231e5286cc1b0b32"
    cluster_size = "7"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre generickd trojandownloader"
    md5_hashes   = "['1ca6f6105690dca2edf9d212b703b30d','35ac94593842605a5c7b0d3d4913a15c','a64c0cb15afc4b9dd469e6e42c8dc0a2']"

  strings:
    $hex_string = { 2c 6a 58 03 11 f7 23 90 cc fc 49 5f b5 af 95 1a 3e d0 c7 2b ca 6b 5f 33 d7 ed 84 25 67 51 1e fe 5c 05 0d 17 3a be ae 4b d9 e9 a4 9e 20 f5 50 56 12 61 c9 43 78 c9 c2 37 d6 64 99 7a 88 63 79 9d }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}