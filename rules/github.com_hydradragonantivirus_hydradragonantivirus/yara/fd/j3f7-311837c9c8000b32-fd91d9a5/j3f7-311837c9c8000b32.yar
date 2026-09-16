rule j3f7_311837c9c8000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.311837c9c8000b32"
    cluster      = "j3f7.311837c9c8000b32"
    cluster_size = "4"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakejquery html script"
    md5_hashes   = "['02031101e0d99ac7815dd8429eb51cf6','63a38e5299cd2aa163473bde01f85a54','b58c76b3d35f3c766e140bc820a4f099']"

  strings:
    $hex_string = "Cookie(\"__cfgoid\",2,1),document.write('<script type=\"text/javasc"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}