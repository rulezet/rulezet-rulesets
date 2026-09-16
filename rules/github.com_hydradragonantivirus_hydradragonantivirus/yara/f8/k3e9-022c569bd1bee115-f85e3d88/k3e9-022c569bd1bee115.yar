rule k3e9_022c569bd1bee115 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.022c569bd1bee115"
    cluster      = "k3e9.022c569bd1bee115"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "qukart backdoor berbew"
    md5_hashes   = "['2b63187081600794acff8b151fe51c31','b817bbd63cdb3f8533815190ee4f3e93','fcdd0d8d4d6d1289be531cca85b1d627']"

  strings:
    $hex_string = { 12 e7 8b da 2c db 7f a6 6e 23 f3 70 79 5c 9f 59 91 99 44 ce 8a 41 d6 d0 50 d4 6d 98 6b 24 46 a0 8e 0a 4d d0 41 7a 0e 9e d6 18 3a a1 69 dc 78 56 16 1c 85 59 91 a0 ba 39 3c 62 87 5b e4 14 ef c9 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}