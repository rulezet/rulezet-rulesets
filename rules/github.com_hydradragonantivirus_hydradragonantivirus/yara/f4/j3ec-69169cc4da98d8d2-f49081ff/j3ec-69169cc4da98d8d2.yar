rule j3ec_69169cc4da98d8d2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.69169cc4da98d8d2"
    cluster      = "j3ec.69169cc4da98d8d2"
    cluster_size = "43"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut advml malicious"
    md5_hashes   = "['0bc5e53a74f387abf97c6d6f58ce5522','0c4e748d326bd21c0f64e6a6aa6b0b4c','63ea0a9b9e0ef440d6afef278c3eb7cd']"

  strings:
    $hex_string = { 45 08 8b 48 3c 03 c8 0f b7 41 14 53 56 0f b7 71 06 33 d2 57 8d 44 08 18 85 f6 76 1b 8b 7d 0c 8b 48 0c 3b f9 72 09 8b 58 08 03 d9 3b fb 72 0a 42 83 c0 28 3b d6 72 e8 33 c0 5f 5e 5b 5d c3 cc cc }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}