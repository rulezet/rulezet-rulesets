rule n3f1_129b3ac1cc000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.129b3ac1cc000b32"
    cluster      = "n3f1.129b3ac1cc000b32"
    cluster_size = "33"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakeinst androidos opfake"
    md5_hashes   = "['081af82129c662a7b694183a25dd26a4','0b99afdac2bdbb35b146ffa3b30e2c9d','7f2c87880bab7d6478fdee8ea7591003']"

  strings:
    $hex_string = { ba ee 98 47 ca 1c be a6 af 8b f2 39 07 64 1a cc 33 8d a1 c3 b7 09 54 12 29 95 e7 6b 56 61 27 c5 40 83 f4 b5 bf f7 17 ff 05 b3 fe 08 fd 90 dd 21 5c c0 a8 4c 55 87 b6 a7 3d b4 7d bb b8 9c 2e a5 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}