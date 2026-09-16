rule o3e9_15b2cc628f836d32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.15b2cc628f836d32"
    cluster      = "o3e9.15b2cc628f836d32"
    cluster_size = "50"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['01f256a2787121de368670df039f188b','0db4fabc847589a6998e300acf3e49f3','5d144804b137da26d6b2c1620968f4e9']"

  strings:
    $hex_string = { c8 c0 ce 2d d0 f7 ae fc ad 08 35 b4 9d ef 54 64 10 f5 2d 27 b3 a3 b0 10 81 56 40 4f fe d4 f3 57 36 e2 57 be 3f eb 62 e1 1b d8 90 1b 59 af 91 45 c5 36 e8 7b b8 92 10 6c 91 50 2c 0b cd 1e 84 ba }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}