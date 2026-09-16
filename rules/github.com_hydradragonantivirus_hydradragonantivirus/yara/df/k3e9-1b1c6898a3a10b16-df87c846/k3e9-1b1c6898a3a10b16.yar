rule k3e9_1b1c6898a3a10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898a3a10b16"
    cluster      = "k3e9.1b1c6898a3a10b16"
    cluster_size = "7757"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta hllp neshuta"
    md5_hashes   = "['00109e4b2ea046cbc3e6b63dd220e160','0019ec18ca324cc218026b70fed9508f','01027256349653168a2ff94e29bcd800']"

  strings:
    $hex_string = { 53 56 8b f0 a1 14 92 40 00 89 08 8b da 85 db 7e 10 b8 ff 00 00 00 e8 e5 b5 ff ff 30 06 46 4b 75 f0 5e 5b c3 55 8b ec 33 c0 55 68 c9 70 40 00 64 ff 30 64 89 20 ff 05 94 a6 40 00 33 c0 5a 59 59 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}