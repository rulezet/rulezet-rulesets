rule o3e7_1d936a49c0000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.1d936a49c0000b32"
    cluster      = "o3e7.1d936a49c0000b32"
    cluster_size = "45"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor itorrent malicious"
    md5_hashes   = "['00f3e5392624d7060f0ffd6cf4b421cf','026ff813e9ae77fafd8e4a2d0c0351f9','5c93878e737bae0bc1537f14c0c1f195']"

  strings:
    $hex_string = { ff 28 37 6e 2f 06 c5 1a a1 aa 3d 3b 93 21 a6 0d 6a 23 42 e5 9b 25 1f c1 4a a4 52 90 30 7f 71 e4 46 f0 45 48 73 7c 14 d1 80 18 c7 de b4 06 85 9e e3 f3 1d 89 0f e7 31 1c b6 57 59 d3 d0 5d ee b3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}