rule j3e9_1649682618aa4ada {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.1649682618aa4ada"
    cluster      = "j3e9.1649682618aa4ada"
    cluster_size = "486"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre zbot generickd"
    md5_hashes   = "['0249da68f16239c7c1986e43ec44a885','0296857a6cb5fd7bba123b6484cdee3e','1f0265b69fca054ec01e3c4f58a0074d']"

  strings:
    $hex_string = { c6 ff 08 14 7d d2 de f4 5b ee 2f 33 1f 4b eb e1 65 7b 2c 39 5b 77 8f af 45 4d 13 4f a4 9b df cc 12 b6 b7 0a 86 38 80 16 85 6e 5b 29 5d a6 ca a7 a4 c3 da 52 4e b3 bb 5f 0d d4 fe 02 9e 72 f9 15 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}