rule j3f4_15a974b6a9146dea {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.15a974b6a9146dea"
    cluster      = "j3f4.15a974b6a9146dea"
    cluster_size = "7"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy atraps backdoor"
    md5_hashes   = "['15358fd5404dd0ccaf79eb43797c1622','225af7eb8bdf1c08659d96ac84251a8a','9951c4eb6faae09b07c747db82642275']"

  strings:
    $hex_string = { 49 6e 66 6f 00 53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 00 41 70 70 6c 69 63 61 74 69 6f 6e 00 67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 00 54 68 72 65 61 64 53 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}