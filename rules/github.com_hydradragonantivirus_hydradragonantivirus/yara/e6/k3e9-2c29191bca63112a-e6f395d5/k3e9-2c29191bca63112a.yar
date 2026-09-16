rule k3e9_2c29191bca63112a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2c29191bca63112a"
    cluster      = "k3e9.2c29191bca63112a"
    cluster_size = "16"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre ipatre trojandownloader"
    md5_hashes   = "['00603838df548e187305cc3ba313c53d','40ab120d3c0aff8015181f5eb841e9f6','fdc3ec9a72b7710e78f36a01c3a65451']"

  strings:
    $hex_string = { 6e 00 64 00 73 00 1b 00 69 00 6e 00 64 00 65 00 78 00 20 00 64 00 61 00 74 00 61 00 20 00 64 00 69 00 63 00 74 00 69 00 6f 00 6e 00 61 00 72 00 79 00 20 00 63 00 6f 00 75 00 6e 00 74 00 00 00 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}