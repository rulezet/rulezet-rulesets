rule k3e9_0914f3e9c8000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0914f3e9c8000b32"
    cluster      = "k3e9.0914f3e9c8000b32"
    cluster_size = "143"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy backdoor injector"
    md5_hashes   = "['00e546c18a8ed5da323b3c754c6f1f0b','01d32226ee1d7481f7890fbb552ad826','8123d94a82261cac76c02e2567d3b1a8']"

  strings:
    $hex_string = { 40 00 8d 49 00 e4 67 40 00 ec 67 40 00 f4 67 40 00 fc 67 40 00 04 68 40 00 0c 68 40 00 14 68 40 00 27 68 40 00 8b 44 8e 1c 89 44 8f 1c 8b 44 8e 18 89 44 8f 18 8b 44 8e 14 89 44 8f 14 8b 44 8e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}