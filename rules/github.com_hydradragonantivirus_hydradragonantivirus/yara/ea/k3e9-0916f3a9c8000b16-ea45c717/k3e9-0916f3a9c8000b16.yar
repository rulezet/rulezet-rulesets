rule k3e9_0916f3a9c8000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0916f3a9c8000b16"
    cluster      = "k3e9.0916f3a9c8000b16"
    cluster_size = "180"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bqbqxwpi injector backdoor"
    md5_hashes   = "['01005fccba730c3da32b124d21a9c0b7','086485ed88fa3973764e5f714c4daaa3','47f2e307e34d9893f3a4039bdfe3c7c1']"

  strings:
    $hex_string = { 21 eb bc 03 95 bc 05 1a 9b a0 33 65 50 0f 1a c0 0b 90 ff 88 17 a1 80 e2 4f dd 27 26 09 14 fc 35 10 d0 d6 1d 3c 48 00 19 b6 a8 0c ba 41 4d a3 91 7f d3 ed 69 01 02 af 49 a6 e4 f3 b8 15 ca 77 2c }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}