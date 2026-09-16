rule p3f7_5b9116c1cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f7.5b9116c1cc000b12"
    cluster      = "p3f7.5b9116c1cc000b12"
    cluster_size = "5"
    filetype     = "ASCII text"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "smsreg androidos riskware"
    md5_hashes   = "['0f881e9012c9603b3673c1a5a86ffcef','41893378143cc1f6c66870e0907915fc','d6e476f43c1589befd638e14c1d828c5']"

  strings:
    $hex_string = { 69 bc c3 65 75 71 6e a0 d7 d2 e4 ca e3 6f 96 fe a2 19 60 2e ac a3 e7 be 95 61 33 b4 1a ae 47 37 06 b9 2d 64 f8 9b 5e b2 e5 6d df 58 ab a5 5a fb 0e 7f 79 15 56 36 26 8b b5 fd bd 80 ec 7c 03 ce }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}