rule k2321_039199aadba30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.039199aadba30912"
    cluster      = "k2321.039199aadba30912"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "symmi swisyn abzf"
    md5_hashes   = "['06a3648e1fd6a9697ed08ea6f70b443e','0f53eedc15e586455627396e90c57d55','835ecf6c5fe35be7389d4140203d49c9']"

  strings:
    $hex_string = { 58 dd 5e 16 71 40 ce 4e 66 4d b0 92 91 54 7d cc cd 75 12 f4 6e f9 5f 0d 9a 5a da 6a ee 21 0f ef 33 49 79 3d de 20 54 a2 b0 0d bb 8d 9c af d2 0c 42 24 5c a1 8f 77 dc f8 69 e4 ab 55 d0 9d e3 ec }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}