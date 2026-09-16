rule k2321_09205923d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09205923d9eb1912"
    cluster      = "k2321.09205923d9eb1912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['35411852f888076054fd50ce908dd2d2','4c738996640924039c4dee1192429e7f','ffbdbef99edc3e0eeabc30addbc3cb99']"

  strings:
    $hex_string = { e5 0c 5f 74 17 d2 27 1b 6c f5 84 de 9f e4 ec 2e b5 62 89 06 cf c7 bf 38 1e 61 78 ea 47 24 7d 73 9e ed df 8c ed 5f dc 8f fd 5a f6 b6 50 c8 f7 cc 34 9a 53 37 43 35 4d d9 c9 0a a5 32 92 05 8b 48 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}