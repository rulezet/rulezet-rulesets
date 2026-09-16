rule j3f4_14655ed24a000130 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.14655ed24a000130"
    cluster      = "j3f4.14655ed24a000130"
    cluster_size = "74"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy onlinegames stealer"
    md5_hashes   = "['0012eaa4e41570d3b7a84425582f2336','02618351132ce345c6a2a909f292f747','27caaf8b50d840b53504b92d2041731d']"

  strings:
    $hex_string = { 6d 2e 54 65 78 74 00 45 6e 63 6f 64 69 6e 67 00 67 65 74 5f 41 53 43 49 49 00 47 65 74 53 74 72 69 6e 67 00 49 6e 64 65 78 4f 66 00 53 75 62 73 74 72 69 6e 67 00 6f 70 5f 49 6e 65 71 75 61 6c }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}