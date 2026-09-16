rule k2321_2914ad2dd89b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad2dd89b0912"
    cluster      = "k2321.2914ad2dd89b0912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy emotet"
    md5_hashes   = "['21e31690e97b6c8c82da0822693f6683','35f883ba4370e317b2410820e5380d12','eea97495936259b92eb6d4f321d613af']"

  strings:
    $hex_string = { fd b3 b9 a1 e1 fc 85 0b 9f 7f f6 d9 cb 2f bf bc 71 c3 86 36 3e af 64 31 11 5f 10 3c d4 72 79 a0 56 0b ca 19 74 5a 72 66 06 3d c4 43 e5 f8 d0 50 a2 3b 6d 01 9e 8c d2 07 77 8b 89 1e 3a 70 40 41 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}