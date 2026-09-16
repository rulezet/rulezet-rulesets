rule o26c0_4916ea48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.4916ea48c0000b12"
    cluster         = "o26c0.4916ea48c0000b12"
    cluster_size    = "215"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious genericrxer kryptik"
    md5_hashes      = "['6533196011104542b566e2e64517b368be302c22','3b53c18879db0bcbb622f4eb2ec005468e6905d1','8f9bf2779ca57dee15a194bfac7a8f12c43f3baa']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.4916ea48c0000b12"

  strings:
    $hex_string = { 31 45 ed 6f e1 19 da 63 b7 c7 a5 7e 38 4f a1 11 12 d8 fa 8d 54 b5 7b 81 51 d7 7c d2 c5 c1 9b 36 ae 67 6e 3a de 68 d6 6d db c9 e5 e1 fd 7f c0 bc 76 8b 2c 3e 86 fc e0 2a 73 b6 dd 16 1a 90 21 93 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}