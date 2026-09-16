rule o26d4_49993bc9c8000916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.49993bc9c8000916"
    cluster         = "o26d4.49993bc9c8000916"
    cluster_size    = "19"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "searchsuite bandoo malicious"
    md5_hashes      = "['89d27a38f67aa1f0bec95df091f9ea437ad6c581','057a3e106d28812339bc0bb0b8b19037c5f70012','17f82bf6a267935356954b1acbbbe9137cf02d1b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.49993bc9c8000916"

  strings:
    $hex_string = { 78 64 43 f7 f8 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 c1 52 53 54 55 56 57 58 59 5a 5b 5c 13 c2 c2 96 87 18 89 23 e7 8a 96 81 82 ce cf 1e 1b d5 a5 22 76 5f 00 01 02 a5 da ae af 32 31 32 16 30 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}