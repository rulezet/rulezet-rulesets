rule p2321_4b9c9cc1cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p2321.4b9c9cc1cc000b12"
    cluster      = "p2321.4b9c9cc1cc000b12"
    cluster_size = "6"
    filetype     = "Zip archive data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "smsreg androidos riskware"
    md5_hashes   = "['35fd8e10f1f4ef2d2e3801593f329934','4a307ed1173f08f122131ba8a7ca00b8','fdd6434ea038f5d009128b4ccb7ff548']"

  strings:
    $hex_string = { f5 ae f7 59 e2 be 03 17 57 14 43 6f f4 4c 4d 4f 7b 29 df 22 25 a5 a4 5c 44 ab 45 7e 70 ef d0 61 a2 6a e5 2f 38 fb e9 ce 82 4a ec 63 9e 18 79 cf 0b 05 0f 49 e3 d6 91 12 c3 1e 66 d2 cb 6c e1 5f }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}