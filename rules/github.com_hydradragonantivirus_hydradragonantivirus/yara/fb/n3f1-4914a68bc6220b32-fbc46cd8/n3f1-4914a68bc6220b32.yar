rule n3f1_4914a68bc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.4914a68bc6220b32"
    cluster      = "n3f1.4914a68bc6220b32"
    cluster_size = "25"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hiddenads androidos afea"
    md5_hashes   = "['0699734d84d91d7fe8eabe034642a1d0','0eea1751f7e3583e71d38dfe6c5f2294','92ffa315d883d4779ad2dfb7a93542f0']"

  strings:
    $hex_string = { 42 23 2a 7d eb c2 77 92 1b d7 30 10 91 bf 08 d6 a5 47 f3 24 3d 9a 80 4f 5a b9 b0 5e 72 7e 01 2b 02 f9 4b 45 c5 99 88 d8 47 b4 70 63 85 a0 56 ac 79 0e d4 c9 f1 62 fb 67 34 e3 64 37 18 a8 f8 94 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}