rule k2321_2914ad6d989b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad6d989b0b12"
    cluster      = "k2321.2914ad6d989b0b12"
    cluster_size = "14"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet zusy"
    md5_hashes   = "['087643a6e07cc94edf0c1c3f074df942','0b22bcdabbcfa4cc54adc99e5cca880e','f48b590a292b2cf63071a09ab2dc8e4d']"

  strings:
    $hex_string = { 9e 7c ed a5 97 f3 b2 b3 fb f7 ea 15 16 14 a8 95 4a 41 94 88 60 00 63 04 ba 90 19 8a 5d 74 3a f0 3f 31 3a 6a c8 80 01 a5 73 e6 bc ff ee bb 67 4e 9f be fe eb af 2e 3c 7e 7b fa e4 e9 a3 87 bf d1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}