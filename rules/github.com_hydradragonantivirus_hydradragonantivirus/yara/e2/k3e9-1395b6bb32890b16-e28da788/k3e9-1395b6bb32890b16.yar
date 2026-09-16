rule k3e9_1395b6bb32890b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1395b6bb32890b16"
    cluster      = "k3e9.1395b6bb32890b16"
    cluster_size = "2158"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ipamor backdoor oyzbaukwkdpb"
    md5_hashes   = "['00303c95aed3d148ad6bef215c6ceb7c','004ce5b6b2198fa187b0e9d02059550e','0163a4f393077304f700f126eecccb51']"

  strings:
    $hex_string = { 10 c1 f8 78 27 50 fe a0 88 c2 12 6d 7c f1 34 60 6a 1b 64 85 ea 3b 55 6c 37 04 11 0e 94 0b 80 9b 68 84 aa 17 30 b9 d8 c3 28 d4 39 f0 9c 5f 9a 15 92 fb 9f 4a c9 7e c6 05 22 1f fa 57 33 41 d6 63 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}