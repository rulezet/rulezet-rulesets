rule k3e9_41342be3a0c44b36 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.41342be3a0c44b36"
    cluster      = "k3e9.41342be3a0c44b36"
    cluster_size = "35"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['020467b8aea71f1291b099fc300bf918','26d4b39111a1036570f84e1f4dded4a0','e03f35d88985b7f37c333416a286d613']"

  strings:
    $hex_string = { cc 6a 0c 68 38 6b 00 01 e8 a3 fb ff ff 33 c0 8b 4d 08 85 c9 74 44 83 f9 ff 74 3f 21 45 fc ba 4d 5a 00 00 66 39 11 75 2b 8b 51 3c 85 d2 7c 24 81 fa 00 00 00 10 73 1c 8d 04 0a 89 45 e4 81 38 50 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}