rule k2321_29251062dbeb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29251062dbeb1932"
    cluster      = "k2321.29251062dbeb1932"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus barys vbkrypt"
    md5_hashes   = "['1bf3414dcf24b722ad5792cfcb10a88f','2390d8423bd36eb16f38d6c5c2a5ae58','dccbd8530a4406b537e80755d7a0683b']"

  strings:
    $hex_string = { 9b d6 dc 1e 71 ce 62 9e 39 e0 28 bd d7 44 5b 2d 0d 56 72 af 89 b2 3a 1a ac 74 73 5b 1f 75 b3 1a f3 64 35 aa 22 57 e8 c8 c9 68 df 6c b4 47 f6 6e bc 1d 8e 5d fb 43 ba 4b 8a 0b f5 7a 54 80 91 69 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}