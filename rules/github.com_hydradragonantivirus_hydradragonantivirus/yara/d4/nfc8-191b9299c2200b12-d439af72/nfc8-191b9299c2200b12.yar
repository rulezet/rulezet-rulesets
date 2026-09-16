rule nfc8_191b9299c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.191b9299c2200b12"
    cluster         = "nfc8.191b9299c2200b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "aiodownloader androidos crepmalware"
    md5_hashes      = "['17120283cb99c53af104a6121f351ce77f73d9fe','4044649c1f4ced1d5920b310128885943844757a','72968a14a000c22626470ee3a87ee08211d4c652']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.191b9299c2200b12"

  strings:
    $hex_string = { 43 74 52 4e 53 66 00 b2 4f 1b 41 2e fd bc 6a 9c f8 d7 83 78 fa 09 e5 c8 b8 b5 af a9 a4 7c 0a f4 f2 d3 94 91 8a 6d 60 5f 5a 48 ee dc ac 8f 7f 75 72 c4 8e 7b fc eb df d0 a0 87 f1 ec e1 da d5 c1 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}