rule k3e9_2b1a4a50d9bb0932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b1a4a50d9bb0932"
    cluster      = "k3e9.2b1a4a50d9bb0932"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ganelp autorun emailworm"
    md5_hashes   = "['07e24239ac4597b03fa325d34e01346a','26cf1f20627e7c68014e80df062127d4','fafb5d7bf5bca37af0e4fbca295d9aba']"

  strings:
    $hex_string = { 4f 67 30 b3 c6 21 7f 5b 1c c2 d5 ee 3f 39 8f 60 e7 0d a3 9c 61 88 fb d7 23 24 f8 1e 62 36 14 5c db 7a 72 9d 38 96 e2 e0 18 3a 89 56 2b 0b 4e f6 8c 99 7b 86 6c b4 af ea c0 45 c7 58 2c 87 07 25 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}