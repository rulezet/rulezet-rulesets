rule k3e9_2b9de945224648f2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b9de945224648f2"
    cluster      = "k3e9.2b9de945224648f2"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['16f5d61982070bd3ad3ec0e34a90e9c8','30c00a286f0f321dfa4d537575ea2629','e73e3655573716f95b5f15cc8dc121b5']"

  strings:
    $hex_string = { 0d 0c 1f 22 20 9d cd 19 7a f8 d2 3a fe d5 6f 9e b9 5b 1c 27 39 7e 62 d9 c5 98 09 4c 89 33 65 d6 e0 68 8f 78 b5 2d 99 91 bd e5 c3 30 0e e8 7b 59 4d e7 86 90 31 41 a4 bf 53 05 c1 9c 43 82 8a ad }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}