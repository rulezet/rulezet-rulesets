rule k3e9_193e75e355b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193e75e355b2f316"
    cluster      = "k3e9.193e75e355b2f316"
    cluster_size = "35"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dealply installcore advml"
    md5_hashes   = "['0056d1315c5e7e519ac6a67087080f38','017c327773ace5e5d4869f887ed44442','90f3145848c860720af28f9da68cda1c']"

  strings:
    $hex_string = { 7b 6c b8 6e 9a fe 05 45 f4 d3 bd 29 91 fb a9 e4 04 f6 77 43 eb a3 73 c0 7a ad 7d 8b 4d a0 de ce 5c f1 49 dc 09 4c 32 46 61 47 48 00 1f 17 b2 22 be 1b 54 fc 02 b4 f0 0c 83 11 e0 e5 4e 56 9d 68 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}