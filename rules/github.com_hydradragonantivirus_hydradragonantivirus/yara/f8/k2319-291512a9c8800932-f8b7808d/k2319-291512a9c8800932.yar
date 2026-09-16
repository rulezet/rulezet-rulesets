rule k2319_291512a9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.291512a9c8800932"
    cluster         = "k2319.291512a9c8800932"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['f301cadd0a5b548aea054a51c6b5115880888254','f153ba1d37d011f9690293e5b0dbe41df9a1e809','b24a5406c46739e92b2837fc6d6a23e1b4830d44']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.291512a9c8800932"

  strings:
    $hex_string = "fined){return z[d];}var R=((7.0E1,80.7E1)>=50.?(37.,0xcc9e2d51):"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}