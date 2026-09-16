rule o26bb_499a95e9ca800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.499a95e9ca800b12"
    cluster         = "o26bb.499a95e9ca800b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious based beeaf"
    md5_hashes      = "['0c8cd34ab3818c02ce4c3a61f65eb36689e16f7f','4dca109896df6def45dd8456042cb49a74439713','1a52e6dd09de86d0e17c0aeb43f51af9589dd48e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.499a95e9ca800b12"

  strings:
    $hex_string = { cf 64 cb 68 a7 2e 70 e7 74 e4 78 a0 8e 8a fc 92 c4 04 3d e5 bc 54 2d 01 10 6a 0f 30 4b 1b 0b b4 3a 24 ec 60 f8 56 a3 78 f3 7c f2 80 76 28 1f 88 84 1c 31 49 f0 5a 02 39 33 b6 2c 04 b8 9d ba 1d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}