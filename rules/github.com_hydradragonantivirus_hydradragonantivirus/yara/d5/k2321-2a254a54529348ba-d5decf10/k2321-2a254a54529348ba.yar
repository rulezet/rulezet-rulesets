rule k2321_2a254a54529348ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2a254a54529348ba"
    cluster      = "k2321.2a254a54529348ba"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy tinba backdoor"
    md5_hashes   = "['43e0da9e12b1d2649aa179e677e4ba55','89042b4812e115cfb2a921cf7efdbf7d','fde518cfd5c6597b08c86018abaf94cb']"

  strings:
    $hex_string = { 75 6d c3 72 ab 8c 61 cb fd 63 e9 be c6 82 30 ec 8e d7 f1 0c bf ea c7 56 93 51 33 7e 4d 53 11 b0 02 8f ed 0a 86 b1 2d 7d 25 2b d3 e1 0d 65 99 b7 3e 1d 6a 81 cf 8a 45 c8 e7 66 04 7f 18 d1 19 58 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}