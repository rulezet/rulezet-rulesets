rule k2321_0913ab0986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0913ab0986220b12"
    cluster      = "k2321.0913ab0986220b12"
    cluster_size = "37"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['05408d88c500ae7048c44b3a5ba26fb9','0dcab52a499bbf6e35fb69a518cad035','860c43639bb4a5715abfb33eaef4fbe4']"

  strings:
    $hex_string = { 11 64 cb 9b 05 f2 e2 af 17 e3 5b 3d d8 f7 aa 6b ea c8 fd 4d 3d 36 26 37 1f 01 3a 03 12 4f 41 7a 26 0d 79 71 7c fe 1a 54 90 9f ba 58 c5 45 1e 1b 30 7b d5 f6 6c 0e f4 e6 5c 62 8e 15 34 2d 98 02 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}