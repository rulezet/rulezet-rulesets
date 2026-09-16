rule o2319_5198e448c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.5198e448c0000b12"
    cluster         = "o2319.5198e448c0000b12"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bitcoinminer coinminer miner"
    md5_hashes      = "['02f5369e1700b6ef8d26e5316eca23b90fe178cf','023688bcb63a86dfd1640f01af5aec5887df2089','406c729addbbd60dae5f8f1a0d56da53189729b9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.5198e448c0000b12"

  strings:
    $hex_string = "Event[g],i=+new Date;(!e||e.options.scrollHijack<i-M)&&(M=i)}),f"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}