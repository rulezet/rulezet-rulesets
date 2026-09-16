rule o3e9_31bb2894ea008932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.31bb2894ea008932"
    cluster      = "o3e9.31bb2894ea008932"
    cluster_size = "135"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious fynx kryptik"
    md5_hashes   = "['00419e760e254e9057c90817a7d51869','036f18da375ee2b034879fd9c4147b32','1f220e103fa856cd653de9e74ba5d1e0']"

  strings:
    $hex_string = { f4 39 f8 39 fc 39 00 3a 00 00 08 3a 0c 3a 10 3a 14 3a 18 3a 00 00 20 3a 24 3a 20 0a 20 0a 00 00 00 00 30 0a 3c 3a 40 3a 44 3a 00 00 4c 3a 00 00 54 3a 58 3a 5c 3a 60 0a 64 3a 68 3a 60 0a 70 0a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}