rule k2319_291594b9ca800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.291594b9ca800b32"
    cluster         = "k2319.291594b9ca800b32"
    cluster_size    = "40"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['d7dc2f3b5b183987feccbf6d154cd75333cae96d','e344434967fc92a6beac5251b19c2c737ecadb93','5a5f05b017a73076a5aee754f01dd040cba59f90']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.291594b9ca800b32"

  strings:
    $hex_string = "119):(3.,27.)))break};var R4v95={'A75':function(X,L){return X!=L"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}