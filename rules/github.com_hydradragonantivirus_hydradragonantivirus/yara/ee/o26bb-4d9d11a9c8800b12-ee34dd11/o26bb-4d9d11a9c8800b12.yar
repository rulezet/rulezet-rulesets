rule o26bb_4d9d11a9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4d9d11a9c8800b12"
    cluster         = "o26bb.4d9d11a9c8800b12"
    cluster_size    = "50"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "filerepmalware malicious razy"
    md5_hashes      = "['d9ef1e1cf3b68def172685751f4c6337a58115cb','34170717b14778a1e3d1a73b53fa3343c78a1ab0','637f8796e6dfd0d31de031d69b4cd77cd1c971a5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4d9d11a9c8800b12"

  strings:
    $hex_string = { ca 83 ef 01 75 dd 8b 45 f8 8b 5d fc 85 c0 77 ae 72 05 83 fb ff 77 a7 5f 66 0f 1f 44 00 00 b8 cd cc cc cc 4e f7 e3 c1 ea 03 8a c2 c0 e0 02 8d 0c 10 02 c9 2a d9 80 c3 30 88 1e 8b da 85 db 75 de }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}