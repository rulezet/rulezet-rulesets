rule o26d5_499b1de9c8800916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d5.499b1de9c8800916"
    cluster         = "o26d5.499b1de9c8800916"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious genx"
    md5_hashes      = "['bd14336762431230e66018e0d457b5e5b9d17ca1','fcba55b9cda0060b5fb1f9d882290a78baa565bb','3e41c73fc074754503d5c4b8ca9de493579e1f82']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d5.499b1de9c8800916"

  strings:
    $hex_string = { 29 ff 2a 2c 2d ed 69 73 85 eb 41 41 6e 8b 2e 27 71 9c 55 60 7b ca 4b 50 7b fe 48 3d 8e fc 4d 5e 8f 7f 26 56 4f 11 af 97 81 00 bd a4 92 08 ad 9c 93 1e b4 a7 9c 18 c6 b6 aa 16 40 41 42 61 22 21 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}