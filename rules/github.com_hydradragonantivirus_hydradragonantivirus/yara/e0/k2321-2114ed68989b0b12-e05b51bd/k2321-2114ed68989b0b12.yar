rule k2321_2114ed68989b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2114ed68989b0b12"
    cluster      = "k2321.2114ed68989b0b12"
    cluster_size = "13"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy emotet"
    md5_hashes   = "['175f30643c6d9ea9358d3b54be5b8956','1c87df8612084211c30ce7374efb4703','fa2ffd2a76cd117a795ace05bf4a483b']"

  strings:
    $hex_string = { 8b e5 d8 d1 63 60 de 07 ef bf d7 ce e7 95 2c 16 97 85 92 5d 48 62 25 c2 12 42 b4 58 a4 94 4a fc d5 2a 44 91 60 7f 1d f6 c4 08 83 d6 a0 22 bd 06 4b c0 1e c4 a7 bc 9c ec 57 5e dc 7e f0 87 1f 70 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}