rule i2319_113c194dcb162916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i2319.113c194dcb162916"
    cluster         = "i2319.113c194dcb162916"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe html script"
    md5_hashes      = "['24ffe860d25aa70682689849efb4cfee5d478c32','f584c55f85d266eee7d0c97904f163a3138a472d','50b529b420b64a491c00f94f931eca943b813889']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i2319.113c194dcb162916"

  strings:
    $hex_string = "w.w3.org/1999/xhtml\">\r\n<head>\r\n<meta http-equiv=\"Content-Type\" c"

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}