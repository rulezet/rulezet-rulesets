rule k26bb_291a5548dcb31932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.291a5548dcb31932"
    cluster         = "k26bb.291a5548dcb31932"
    cluster_size    = "47"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "remoteadmin winvnc riskware"
    md5_hashes      = "['7c163a5874d01d6061fe8d220900f27eb6d5b13c','562acab4caba92b13403b90ec64b6b8dbcb91bfa','0aa59432d04c79139b378e7e7b5ffdfdd8ac9922']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.291a5548dcb31932"

  strings:
    $hex_string = { 5b 72 02 8b c7 50 87 53 dd 1a c5 cc 0d 0c 36 d9 01 e0 c3 80 17 b8 ee 2b f8 60 ec 11 27 6a 1c e8 49 59 73 dc fa 8d 56 33 d2 3b da 89 fd 74 29 7d 69 db 54 f0 92 0a fb 8d 4b a7 83 c0 05 d0 9e 6c }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}