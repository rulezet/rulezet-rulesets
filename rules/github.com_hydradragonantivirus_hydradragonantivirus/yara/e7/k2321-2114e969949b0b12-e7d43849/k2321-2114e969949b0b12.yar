rule k2321_2114e969949b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2114e969949b0b12"
    cluster      = "k2321.2114e969949b0b12"
    cluster_size = "11"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet vbkrypt"
    md5_hashes   = "['3876d80c8f8a1e086ce87d538400a8bc','5f0e7c123de16c34b97cf13a8693915c','eed2b5069065487d22737c0d23d13608']"

  strings:
    $hex_string = { 9d af bd 76 fc e8 51 87 dd 66 b1 58 8e 1d 3d 06 e6 7d f0 fe 7b ed 7c 5e c9 62 71 59 28 d9 85 24 56 22 2c 21 44 8b 45 4a a9 c4 5f ad 42 14 09 f6 d7 61 4f 8c 30 68 0d 2a d2 6b b0 04 ec 41 7c ca }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}