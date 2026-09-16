rule k3e9_668c2b25c92b6916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.668c2b25c92b6916"
    cluster      = "k3e9.668c2b25c92b6916"
    cluster_size = "179"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbna vobfus chinky"
    md5_hashes   = "['08e9ea4c5cfcded006bfba6957d9f623','099a9d8e44ea45cd963e6d06c89e8b4f','467cb0b9681beff937fb54117e98c6ed']"

  strings:
    $hex_string = { 2a 46 58 ff 10 80 07 03 00 6b 56 ff 70 54 ff 35 58 ff 00 0b 6b 54 ff f4 ff c6 1c 13 03 00 19 80 0c 00 76 1a 00 2a 23 4c ff 6c 78 ff e4 f4 ff fe 5d 20 10 2f 4c ff 00 1d 6c 78 ff e4 5e 1b 00 04 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}