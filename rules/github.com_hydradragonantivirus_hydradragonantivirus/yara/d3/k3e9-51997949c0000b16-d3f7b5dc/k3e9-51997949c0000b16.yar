rule k3e9_51997949c0000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.51997949c0000b16"
    cluster      = "k3e9.51997949c0000b16"
    cluster_size = "33"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol servstart bmgfas"
    md5_hashes   = "['103859ec87d460fff31e9355f4d0503e','1a0989c6a9e0fadc195a18b58cd260cb','a66164b98b9f42fb98d5a5983c1d3559']"

  strings:
    $hex_string = { 53 48 4c 57 41 50 49 2e 64 6c 6c 00 55 53 45 52 33 32 2e 64 6c 6c 00 57 53 32 5f 33 32 2e 64 6c 6c 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}