rule o3e9_4b124e86d7a74912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.4b124e86d7a74912"
    cluster      = "o3e9.4b124e86d7a74912"
    cluster_size = "204"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "blackv malicious chinad"
    md5_hashes   = "['00c4ba7ed1ea555a81c9a54b69eccfdf','018c7d11c237197a4fc2e89c880b1ffa','14539c19512cc1aa460e891fbd95fe53']"

  strings:
    $hex_string = { bd 8a 2b 6b 8a 4e e2 23 f3 04 1f 68 04 99 da 90 6b 38 76 76 42 76 2e 5f ba 26 e0 8c 96 a8 2f f4 60 ed e4 e8 d9 65 0e fa 58 dd 7f 74 f6 6d 26 9c 64 10 de e4 8d 6b e9 ec be 4b 78 a4 be 8f b4 8e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}