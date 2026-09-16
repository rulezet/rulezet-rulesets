rule o3e9_4986b4c4cec30932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.4986b4c4cec30932"
    cluster      = "o3e9.4986b4c4cec30932"
    cluster_size = "133"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "strictor dealply malicious"
    md5_hashes   = "['0040151d41babbb0f364de6844566542','00d55695a162dd371a450b96a6f2f716','1222e6da905c09899ccc164cea9aa7e0']"

  strings:
    $hex_string = { 00 28 00 25 00 64 00 29 00 11 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 63 00 6f 00 64 00 65 00 20 00 70 00 61 00 67 00 65 00 08 00 46 00 65 00 62 00 72 00 75 00 61 00 72 00 79 00 05 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}