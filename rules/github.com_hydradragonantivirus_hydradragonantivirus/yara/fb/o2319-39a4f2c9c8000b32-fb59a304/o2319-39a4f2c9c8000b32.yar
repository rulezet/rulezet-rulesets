rule o2319_39a4f2c9c8000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.39a4f2c9c8000b32"
    cluster         = "o2319.39a4f2c9c8000b32"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos coinminer coinhive"
    md5_hashes      = "['83f71e5db1a52333a02d5b15302b6abb25da4cd8','829b112e9635caf39a1a8e4863da1aac6c0279a3','e603ec25ad4950ac072ce77a260a797de04d0332']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.39a4f2c9c8000b32"

  strings:
    $hex_string = "0]),a},PSEUDO:function(a){var b,c=!a[6]&&a[2];return X.CHILD.tes"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}