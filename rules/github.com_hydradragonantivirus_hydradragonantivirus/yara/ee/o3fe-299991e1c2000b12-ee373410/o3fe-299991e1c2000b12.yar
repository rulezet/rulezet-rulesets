rule o3fe_299991e1c2000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3fe.299991e1c2000b12"
    cluster      = "o3fe.299991e1c2000b12"
    cluster_size = "229"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bitmin coinminer bitcoinminer"
    md5_hashes   = "['0000c2ad7facce74b89bf75d7e539f0b','03898f6535441db5dbe32fac4ba3ea48','1135efe8adbd779382645d192306cf27']"

  strings:
    $hex_string = { 00 d6 fa 0e 77 cb a3 de 89 36 7d d3 6e b4 72 a6 6a d7 ae 35 7c 70 cd aa 17 be 03 ab 0b 9a 87 4e 73 14 a9 12 8f 51 1d 16 3d 0d 40 53 3e b9 e6 6d 37 4a 92 e1 ff b3 a0 c5 f6 31 3a 59 e0 b5 dd 5b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}