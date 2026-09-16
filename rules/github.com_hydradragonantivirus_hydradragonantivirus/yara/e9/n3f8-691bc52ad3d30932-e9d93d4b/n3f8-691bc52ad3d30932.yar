rule n3f8_691bc52ad3d30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.691bc52ad3d30932"
    cluster         = "n3f8.691bc52ad3d30932"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "droidkungfu androidos kungfu"
    md5_hashes      = "['da16a6ffc7fd3cf7ee0526c683520c0696eb63f3','db5ba274a859b61d5748000b20da8c2263c3b596','040bdeb9f168637c36e191c099658956182e7732']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.691bc52ad3d30932"

  strings:
    $hex_string = { bd ef bc 8c e8 af b7 e5 9c a8 e9 80 9a e7 9f a5 e4 b8 ad e9 80 89 e6 8b a9 22 e5 85 b3 e9 97 ad 55 53 42 20 e5 ad 98 e5 82 a8 22 00 03 53 44 4b 00 12 53 44 4b 47 65 74 41 70 70 4e 61 6d 65 45 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}