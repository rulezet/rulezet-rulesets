rule k2321_2914a94d989b0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914a94d989b0b32"
    cluster      = "k2321.2914a94d989b0b32"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy tinba vbkrypt"
    md5_hashes   = "['5541ccd3685f2ce186fc023704727f93','860ecf58a73b4ad463e5f7e0dadb7d1e','efe21826309a80b4c811d6c157820721']"

  strings:
    $hex_string = { f5 35 0c 5c 79 9a 6b fd 87 9a 3e 59 cb a0 b6 08 06 5a 63 88 9e 21 ac 3d 4e a5 7f 93 b1 b7 e2 c7 94 99 cc 72 c9 9f 73 23 19 53 f8 5f 3b f1 4f 54 4d e7 78 51 82 b1 44 82 e3 2a 61 92 48 bb 00 74 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}