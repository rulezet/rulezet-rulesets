rule k2328_6ebb7949c8000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2328.6ebb7949c8000932"
    cluster         = "k2328.6ebb7949c8000932"
    cluster_size    = "84"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe html iframeref"
    md5_hashes      = "['277f343f6253a63c78c39ee034c8a2fdaf3b2919','9b2ba04a6d30e796a22edabe8b4b908811da5f5e','fe3a620a261b987fbe0f32e253c58367ba524da4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2328.6ebb7949c8000932"

  strings:
    $hex_string = { 70 3b 69 64 3d 32 30 26 61 6d 70 3b 49 74 65 6d 69 64 3d 34 32 22 20 63 6c 61 73 73 3d 22 6d 61 69 6e 6c 65 76 65 6c 22 20 3e 46 65 6c fc 6c 65 74 6b e9 70 7a f5 20 61 6e 79 61 67 6f 6b 3c 2f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}