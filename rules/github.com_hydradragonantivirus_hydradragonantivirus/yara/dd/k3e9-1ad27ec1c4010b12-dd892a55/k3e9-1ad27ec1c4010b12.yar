rule k3e9_1ad27ec1c4010b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1ad27ec1c4010b12"
    cluster      = "k3e9.1ad27ec1c4010b12"
    cluster_size = "10"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "chir runouce email"
    md5_hashes   = "['03eacc05bbdaa267205137703b5ef487','4aaa648749250f1c0d3ce7b8ac81e373','f4bdfa51467c5866a20afc6555d61cc5']"

  strings:
    $hex_string = { 34 58 66 3d 60 e8 0f 84 86 00 00 00 81 4b 24 00 00 00 e0 6a 02 6a 00 ff 75 08 ff 56 3c 83 f8 ff 74 70 50 05 fc 19 00 00 2b 43 14 89 43 10 8b 53 08 3b c2 72 16 89 43 08 8b 4f 38 49 03 c1 03 d1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}