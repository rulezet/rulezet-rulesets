rule o3f9_611493c9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f9.611493c9cc000b12"
    cluster      = "o3f9.611493c9cc000b12"
    cluster_size = "78"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy lyposit malicious"
    md5_hashes   = "['022a5f400921f56f8165bc80cff6ca98','1274738144dfbaf1377f99cc6080b6a5','a39a5106927d58997bcc06020f87162f']"

  strings:
    $hex_string = { 75 31 da 95 ef 9f b7 af e9 97 f2 73 b2 45 8a b4 86 50 d9 e7 12 fe 90 ae c2 d1 db 98 22 b1 fb 6d e2 c6 7b 6c 5e 88 15 47 e8 74 26 0d 46 10 ec 25 76 c7 a5 62 c8 6e 29 48 9b 5a d5 58 8f 30 c5 de }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}