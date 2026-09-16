rule k2321_2914ad6590bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad6590bb0b12"
    cluster      = "k2321.2914ad6590bb0b12"
    cluster_size = "7"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy emotet"
    md5_hashes   = "['24f73f8cbffc560703336014bd9d296a','55b2a5cf15dd297a698a225ba7287b68','fa00fcaa5f7c20db37472d8ec75b2aeb']"

  strings:
    $hex_string = { 94 a4 49 13 c6 97 2d 58 b0 7d fb b6 0f 3f f8 f0 d3 4f 3f db b3 67 cf 6e 3c 3e d9 fd c9 27 58 7c f2 f1 c7 1f bf f5 d6 5b ab 57 ae ca 9e 9c 39 a0 77 ef d8 88 08 20 1a ac 56 85 eb 83 a3 42 43 a2 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}