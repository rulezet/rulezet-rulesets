rule k3e9_4563c22679b314b5 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4563c22679b314b5"
    cluster      = "k3e9.4563c22679b314b5"
    cluster_size = "30"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['13551acad030c839dd5a5c72b326dacb','4790ec984b19f38a28b6a5e7cf537ed8','cfa6eadeb4f11592f5c60fb0160d371f']"

  strings:
    $hex_string = { 43 3b 3b 3d 3f 31 2d 49 3a 2b 24 54 3a 2b 26 65 3d 2f 2d 7d 3c 2f 2b 94 39 27 22 a5 44 3f 41 bc 5b 6d 7e d8 54 6c a2 ea 61 88 c7 f6 62 89 c6 f8 63 8b c7 f8 49 4a 5a e3 38 25 1f c0 38 29 26 95 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}