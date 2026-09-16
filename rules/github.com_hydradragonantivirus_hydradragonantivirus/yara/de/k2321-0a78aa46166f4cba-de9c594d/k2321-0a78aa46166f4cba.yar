rule k2321_0a78aa46166f4cba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0a78aa46166f4cba"
    cluster      = "k2321.0a78aa46166f4cba"
    cluster_size = "18"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['11e2e97c1548f28dbceb5fa2d3bf70bc','127ffbc2e4d15f845b28fed191784da1','d825c4593550dde564239fd41283e8ac']"

  strings:
    $hex_string = { 41 b5 fc d7 c6 ed 63 ea 98 a8 f8 85 0b bc d6 9c 03 96 8a 13 0e f4 97 eb 7f 91 37 2c c4 3f da 0f 72 77 82 1c 9d 95 1f bb ff 35 2e aa 10 d0 83 4c 16 a4 fd 7a 6c 13 4b 06 2f 34 f2 68 e7 38 b6 15 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}