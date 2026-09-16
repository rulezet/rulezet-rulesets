rule o3e9_4b956a48c0000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.4b956a48c0000b16"
    cluster      = "o3e9.4b956a48c0000b16"
    cluster_size = "20"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur gena"
    md5_hashes   = "['47703f0dd7bbfffb1f9fa903ed603ced','4786196ed20bc5437bcd10dd2b2d8e4f','e29efd93f224ab87f51891a0a0c0ecaf']"

  strings:
    $hex_string = { b3 b3 b3 ff e6 e5 e5 ff f3 fc fd ff 90 de f2 ff 43 cc f1 ff 49 ca eb ff 06 c1 f2 ff 14 a1 c7 ff 9f 7c 51 ff fe b4 56 ff fd c9 88 ff fe e8 d1 ff fe cc ac ff 97 6b 68 ff 00 00 00 8f 02 02 02 2f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}