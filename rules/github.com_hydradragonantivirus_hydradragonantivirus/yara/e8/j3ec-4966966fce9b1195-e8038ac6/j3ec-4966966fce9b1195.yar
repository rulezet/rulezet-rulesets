rule j3ec_4966966fce9b1195 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.4966966fce9b1195"
    cluster      = "j3ec.4966966fce9b1195"
    cluster_size = "319"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector aqvmvuji infector"
    md5_hashes   = "['00cf16b6c3e676018b05665dc1c37eac','00e96ede508a0b25f17894d95e1965ee','0bb6dc2380d34b0e25ca90ed24d7ced7']"

  strings:
    $hex_string = { ed eb 79 7c 8f fa 42 52 a1 62 6f ab 0c 31 4f 24 23 34 86 fe 6e d4 7b 51 f5 10 fd e7 62 b1 4a 4d 6c 08 6a ee 14 2d c2 a5 4c 2b 5c 6b 11 cb 06 e4 0c c4 19 47 91 9f a8 23 ef 73 92 e3 db 7e 39 25 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}