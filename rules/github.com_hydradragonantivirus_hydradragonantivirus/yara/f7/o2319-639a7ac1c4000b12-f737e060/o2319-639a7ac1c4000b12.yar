rule o2319_639a7ac1c4000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.639a7ac1c4000b12"
    cluster         = "o2319.639a7ac1c4000b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "faceliker likejack classic"
    md5_hashes      = "['6ef857e5622d82c5837ca5c830c02dfd83642d19','feac2c4abd784c19914fe4d726d713936c92730a','d6bbfe75fd917773d267c9591eaaa717f2c5509d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.639a7ac1c4000b12"

  strings:
    $hex_string = "zed expression: \"+q)},CHILD:function(g,h){var l=h[1],m=g;switch("

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}