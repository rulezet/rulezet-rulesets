rule n3f8_5a06e44980000910 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.5a06e44980000910"
    cluster         = "n3f8.5a06e44980000910"
    cluster_size    = "51"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos banker piom"
    md5_hashes      = "['735c7def8189e67b21a31351846cc0ba09f4fa2a','df079495700f3f9964d83db3404b1199f0924b56','19ce39181fa122cc57b8991a612ca3697fe54448']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.5a06e44980000910"

  strings:
    $hex_string = { 10 6c 01 04 00 0a 01 6e 10 62 01 04 00 0c 00 72 30 18 08 50 06 0a 00 38 00 f3 ff 54 42 2f 00 72 10 f8 07 02 00 0a 02 54 43 33 00 b1 12 71 20 80 01 23 00 39 01 e5 ff 6e 10 60 01 04 00 28 e0 03 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}