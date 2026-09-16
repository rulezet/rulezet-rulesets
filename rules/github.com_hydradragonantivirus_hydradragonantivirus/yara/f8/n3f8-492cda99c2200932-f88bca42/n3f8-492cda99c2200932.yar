rule n3f8_492cda99c2200932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.492cda99c2200932"
    cluster         = "n3f8.492cda99c2200932"
    cluster_size    = "44"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smsspy androidos smsthief"
    md5_hashes      = "['6511829f289f3114a43c666759965d4a872f20c7','c4382fc7ddb58b7d30ccdaa7d3fc1f8a8e9efa42','ab3ce70137c4a98793d781ec37b9c98f530e2cdb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.492cda99c2200932"

  strings:
    $hex_string = { 76 61 4d 61 69 6c 2e 00 03 4a 75 6c 00 03 4a 75 6e 00 09 4b 45 45 50 5f 53 45 45 4e 00 07 4b 45 59 57 4f 52 44 00 07 4b 53 43 35 36 30 31 00 08 4b 65 79 77 6f 72 64 73 00 01 4c 00 06 4c 41 52 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}