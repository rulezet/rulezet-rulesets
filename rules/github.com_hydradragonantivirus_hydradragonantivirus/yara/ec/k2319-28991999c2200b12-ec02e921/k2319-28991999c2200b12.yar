rule k2319_28991999c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.28991999c2200b12"
    cluster         = "k2319.28991999c2200b12"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script iframe exploit"
    md5_hashes      = "['6609c6b82dc06e85e3372a752832047e1fead6e6','73bfdf6f861db1f44fc7924ee6999c2c1e912327','558347ced1f4055fcc7aaefb65768feed800c39e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.28991999c2200b12"

  strings:
    $hex_string = "3}|[a-z]{2}|master)\\//,\n    cookieAge: 365 * Cookies.SECS_IN_DAY"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}