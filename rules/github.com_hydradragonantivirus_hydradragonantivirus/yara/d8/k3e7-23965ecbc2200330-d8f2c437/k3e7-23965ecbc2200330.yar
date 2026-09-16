rule k3e7_23965ecbc2200330 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.23965ecbc2200330"
    cluster      = "k3e7.23965ecbc2200330"
    cluster_size = "15"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "linkury toolbar classic"
    md5_hashes   = "['017ea0a376051313f47d4ebeba560fa5','048dff7e5d9aaeda8483f46b42c9b7bd','e44297921be869d322fa7944ddfe5183']"

  strings:
    $hex_string = { 37 03 3d 01 8c 05 41 01 b5 05 65 00 37 03 86 00 35 06 6b 01 86 02 00 00 00 3c 4d 6f 64 75 6c 65 3e 00 75 6f 75 5f 41 50 53 46 52 65 63 2e 65 78 65 00 44 65 76 49 64 47 65 6e 00 55 70 64 61 74 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}