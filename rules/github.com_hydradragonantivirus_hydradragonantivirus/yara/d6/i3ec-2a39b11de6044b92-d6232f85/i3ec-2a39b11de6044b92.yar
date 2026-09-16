rule i3ec_2a39b11de6044b92 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ec.2a39b11de6044b92"
    cluster      = "i3ec.2a39b11de6044b92"
    cluster_size = "83"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector malicious ccmw"
    md5_hashes   = "['01f2d546268e9451109dea3ed28ac687','0291a4727b7b3c344716f83a39e34357','1b33aff7b4284d881c9060162462e4ed']"

  strings:
    $hex_string = { 02 33 d2 02 2b d2 02 01 02 f7 e3 06 02 02 2b f8 04 8b d8 2b fb 06 02 02 85 ff 04 8b df 85 db 16 02 08 7f 06 81 c7 ff ff ff 7f 0e 7f 0c 81 c7 78 56 34 12 81 c7 87 a9 cb 6d 03 01 03 89 7d 00 05 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}