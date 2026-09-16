rule n3ed_0ca3390f1a1b1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a1b1932"
    cluster      = "n3ed.0ca3390f1a1b1932"
    cluster_size = "30"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bpchjo"
    md5_hashes   = "['a1c329ddd78db2e224d5794ac325e35a','a20b3c9cfe3fc99e7a483f0d5c2e7d58','e953503430816b28d36a07c40cd458fa']"

  strings:
    $hex_string = { 55 57 6a 40 5f 4a 81 e2 00 dc e3 03 81 c2 4b 59 4d 43 3b cf 8b ea 7d 02 8b f9 3b fb 76 1b 56 8d 70 1c ff 36 8b c5 e8 91 fa ff ff 84 c0 59 74 0d 43 83 c6 10 3b df 72 ea 5e 5f 5d 5b c3 68 67 69 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}