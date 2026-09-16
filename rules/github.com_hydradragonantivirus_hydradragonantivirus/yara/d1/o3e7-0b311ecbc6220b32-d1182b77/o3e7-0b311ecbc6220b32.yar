rule o3e7_0b311ecbc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.0b311ecbc6220b32"
    cluster      = "o3e7.0b311ecbc6220b32"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr malicious banker"
    md5_hashes   = "['3ed8ccd44cf1d1f9beabdb4b6668ad7d','499e571b23fe14964af6794b5769e446','77cc35170d5c881407cf6c7803ddab33']"

  strings:
    $hex_string = { e5 11 67 45 ac 20 60 2c 72 be 65 96 6b bc fd 6a 63 d2 b8 c1 a4 48 cb aa b6 53 1f 9c 1e f3 ab eb 58 ae 7d ad ba e0 a3 a7 5b cf 8c 88 b5 3e 19 f2 5a 26 23 d8 25 bf ec 2a 10 8a 52 00 a1 22 9f 57 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}