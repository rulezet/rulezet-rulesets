rule k2319_2b934d49c2220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2319.2b934d49c2220b32"
    cluster      = "k2319.2b934d49c2220b32"
    cluster_size = "5"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe html exploit"
    md5_hashes   = "['474b44760b9c575d2e4ef70871c52675','5a051baa1c0e3e4c75ace507831f2e77','f851bd843028bf1f26497c7a60619c7d']"

  strings:
    $hex_string = "<td  width=\"100%\" style=\"background-image: url(templates/niche2/"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}