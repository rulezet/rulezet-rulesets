rule o3e9_19b358eb14714cf3 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.19b358eb14714cf3"
    cluster      = "o3e9.19b358eb14714cf3"
    cluster_size = "257"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['005f0be7888507cc4c8fb01cd4145731','00f73cb734c30723381dc2aa0ebe5d4c','0bd183e7f021c8fabea5781112670c18']"

  strings:
    $hex_string = { c0 c9 44 df 0a bc 60 1b d9 53 72 13 6c b5 60 10 e8 16 de c5 c8 53 74 56 0b 62 96 6a 5e ef fe 31 f0 03 b9 4b 5d c0 13 ee 24 c2 78 62 1a 76 d4 78 b5 c7 d8 21 f1 42 a4 55 28 40 9c a3 6e 09 3a 09 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}