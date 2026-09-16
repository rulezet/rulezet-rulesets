rule n3f1_491e9299c2200932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.491e9299c2200932"
    cluster      = "n3f1.491e9299c2200932"
    cluster_size = "80"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "obfus androidos andr"
    md5_hashes   = "['05ccfcbae54e5722a04b30ee0d91272e','064008eb3f684d2b77d9fc067d5151b8','35bba3bb3393ee4361238e3b300fb93f']"

  strings:
    $hex_string = { 07 80 3b 0d b5 c6 d0 98 6d 16 8a 29 f5 7d 9a 05 09 6e 5a ad aa 6a 9b 82 34 0c 65 7d 7f bf d9 6c 58 9c 99 55 8b 59 d7 2e f6 e6 3f da f8 16 37 cd bb 8d ce 17 e8 fa 56 8e 1e c0 6f 4c 25 f2 14 1b }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}