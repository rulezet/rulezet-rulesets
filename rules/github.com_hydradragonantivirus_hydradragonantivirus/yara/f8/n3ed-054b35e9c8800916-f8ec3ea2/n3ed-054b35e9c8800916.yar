rule n3ed_054b35e9c8800916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.054b35e9c8800916"
    cluster      = "n3ed.054b35e9c8800916"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "floxif pioneer malicious"
    md5_hashes   = "['32e050729fa2458b017799f777414b90','d40695fe06856fc5ce90a7279a36d00d','d5c9e0d43fd307224008fd0c739988de']"

  strings:
    $hex_string = { 0f 83 27 61 2f 39 be 4c 4f cb a7 d6 e4 c4 08 47 d3 c2 e3 c6 1c 9c b9 fc 86 c8 6e 05 59 77 95 04 3e d1 11 4c 25 46 78 c0 dc 15 1e d9 49 f7 50 cf 73 ec 2d ee f4 d9 b5 d5 4e 8f 31 a8 f5 de 21 db }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}