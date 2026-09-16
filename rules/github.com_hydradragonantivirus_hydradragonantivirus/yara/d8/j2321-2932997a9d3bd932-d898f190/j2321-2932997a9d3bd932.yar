rule j2321_2932997a9d3bd932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.2932997a9d3bd932"
    cluster      = "j2321.2932997a9d3bd932"
    cluster_size = "12"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bavs upatre kryptik"
    md5_hashes   = "['0f1ec050eef4252471a597f860b00c30','2d5200b2d416a344685c49dfba1e05e7','efa815d07b5ee0d7d265e4dcd6a8e870']"

  strings:
    $hex_string = { 0e f2 76 1b 23 3f 37 ef d9 66 ac 87 4f 80 a5 cd b3 3d 9e a8 a1 71 39 f1 27 6a a6 de e3 89 0a 58 7b 3c 61 67 5a 8a f3 09 9b 3c 9f 45 1a 4b 40 47 b5 7c 8c c8 11 fd 35 74 92 1c 22 85 f4 59 7d 20 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}