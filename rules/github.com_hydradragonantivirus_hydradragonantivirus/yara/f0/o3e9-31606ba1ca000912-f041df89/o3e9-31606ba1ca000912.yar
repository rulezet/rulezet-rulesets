rule o3e9_31606ba1ca000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.31606ba1ca000912"
    cluster      = "o3e9.31606ba1ca000912"
    cluster_size = "2590"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "downloadsponsor malicious unwanted"
    md5_hashes   = "['00461fb44249659bd46d2640e776b159','006f8f33d03b86b9a20f50de55b927b5','02179f1b320f35c0601cf859cef5bf66']"

  strings:
    $hex_string = { 6f c4 7d 71 52 a7 1b 20 7b 1f 48 47 d4 b9 e7 44 7c be 6e a4 eb f4 c5 21 37 e9 3e 65 15 21 e4 d4 b8 c2 18 63 c6 29 a8 b5 a4 bb 88 0a ba b8 da e3 cb 98 43 bc 8e 53 c4 57 9b 7b 83 2c 22 4e b9 7f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}