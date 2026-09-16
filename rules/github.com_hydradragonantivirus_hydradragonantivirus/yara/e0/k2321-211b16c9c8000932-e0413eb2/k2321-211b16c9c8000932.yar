rule k2321_211b16c9c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.211b16c9c8000932"
    cluster      = "k2321.211b16c9c8000932"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol servstart ageneric"
    md5_hashes   = "['32a2b51b366dc8e9a262686e137e729b','924fb589bbe9b118fac9fcf19aa7735f','ea49757e49a4e8417473076ccbbf1478']"

  strings:
    $hex_string = { ee 16 46 b5 6d 31 e3 be cf 97 86 6b 36 35 a1 ec f6 76 22 2e 0e 3e c2 db 51 e9 b0 92 17 13 f3 71 a4 b7 77 90 99 95 94 82 5c 14 eb 5f fc 5e b1 98 1e 09 c3 96 7d 24 7a 21 d9 a3 1e c0 fb e8 9c 87 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}