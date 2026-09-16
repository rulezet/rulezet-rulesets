rule k2321_29259160d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29259160d9eb1912"
    cluster      = "k2321.29259160d9eb1912"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi vbkrypt"
    md5_hashes   = "['23b2db415583847bdd900ec1f73b7f0a','3c7be4c906433901d33cd162ebe1e7e3','4e6578bce015a184895088fb45e685b1']"

  strings:
    $hex_string = { a2 23 ab 6f 52 b2 5b 27 ca 54 95 e2 68 d8 55 df f3 92 33 fb 7c e7 4b 5a a7 a0 1a ed a1 9e 01 c3 20 3b af dc a3 28 73 d1 7b 4e 32 30 dd 22 17 1b 96 ec 62 43 9a b6 bd 00 82 0c c2 4d 10 46 0b 34 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}