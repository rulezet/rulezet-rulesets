rule k2321_09259862d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09259862d9eb1912"
    cluster      = "k2321.09259862d9eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi vbkrypt"
    md5_hashes   = "['0052f418ad4680284b65641039ec6954','09e6e1301e73d3f6077dbe38bd3cf79c','52cec0b59b6969660f91afbfc0600b9a']"

  strings:
    $hex_string = { c9 6a 54 45 ae d0 91 93 d1 be d9 68 8f ec dd 78 3b 1c bb f6 87 74 97 14 17 ea f5 a8 00 23 d3 e6 3a 3a 32 b5 ee d6 94 02 18 75 b7 6c e1 f2 cf 9b 53 48 7c 5a af 86 b6 79 dd 27 35 7d c2 47 64 15 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}