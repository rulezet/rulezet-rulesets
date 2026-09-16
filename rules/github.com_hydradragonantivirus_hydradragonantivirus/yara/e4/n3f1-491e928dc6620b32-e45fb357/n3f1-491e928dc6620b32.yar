rule n3f1_491e928dc6620b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.491e928dc6620b32"
    cluster      = "n3f1.491e928dc6620b32"
    cluster_size = "13"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "obfus androidos andr"
    md5_hashes   = "['04848568d3de9a70d8f32031935030d7','0877518cd2b9413b3cb01326a870cacc','e79a57493f333cbb71eec74fb83218ff']"

  strings:
    $hex_string = { 0b 00 8a cf bf f7 1d 40 4f b8 bb 5d b1 4b 1e 42 e2 5e 6c 73 aa d1 b0 2b 19 b7 c1 c3 88 11 63 4a a8 0c 6e 3a cb 5b 23 c5 60 51 1a 69 18 55 c8 18 8d fd c9 e6 57 c0 94 3c 9b 39 e0 7c 3e e3 b4 9c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}