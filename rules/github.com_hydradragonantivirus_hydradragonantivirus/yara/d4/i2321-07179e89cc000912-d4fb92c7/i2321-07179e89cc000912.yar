rule i2321_07179e89cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.07179e89cc000912"
    cluster      = "i2321.07179e89cc000912"
    cluster_size = "7"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['00717130bb272f058bf2a074fb456a42','321b5117035911a9665ffd8c856b534b','f49d35a72c4a1c85703293975f52f62f']"

  strings:
    $hex_string = { 57 6f 9e 29 85 a9 c9 d1 89 8d 78 bd 7b a2 f2 c2 f8 62 a5 71 b1 58 ae 2d 56 46 2f c4 9e cb 69 ec 99 38 bb e3 95 8b 69 e0 f0 48 31 4e 70 a3 c5 5a 9c 71 1c eb e8 7c 6d b6 d2 48 17 12 5b 4c 1e 1b }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}