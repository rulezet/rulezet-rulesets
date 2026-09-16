rule o3e9_1529ac6a9ac3691a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1529ac6a9ac3691a"
    cluster      = "o3e9.1529ac6a9ac3691a"
    cluster_size = "743"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster bundler installmonstr"
    md5_hashes   = "['00598413dd37c914517788f20527accc','00e2ece8e8b097a6ba2f0ad512877c0b','091f5cf6e9ec7a340325cb68ea74d430']"

  strings:
    $hex_string = { 3e 83 99 28 2b f1 cd 97 a2 bd 18 aa 85 36 ac 76 af ce 09 d8 fc 7f 12 2d d9 78 fd 6e 7d 1e ec 72 54 8a 84 b2 44 32 8b 0a d2 30 48 cc 22 d4 b8 c5 4e 0b 33 ae 02 c8 d1 4c 04 f7 d6 29 75 95 05 80 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}