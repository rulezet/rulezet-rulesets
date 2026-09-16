rule i3ed_525ee454d8bb7b65 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.525ee454d8bb7b65"
    cluster      = "i3ed.525ee454d8bb7b65"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamarue uztub bundpil"
    md5_hashes   = "['141dbd25adfdab7379c2fd71d46a54df','aeb043fcd673c7884faacf4e0db868d5','b70dfadc2048a9c7b157a65a8eb12e22']"

  strings:
    $hex_string = { d8 3b 0d f4 30 00 10 73 1f 8b 15 e8 30 00 10 03 55 d8 0f b6 02 33 45 ec 03 45 fc 8b 0d e8 30 00 10 03 4d d8 88 01 eb cd ff 15 e8 30 00 10 81 7d 14 00 70 00 00 75 05 e8 90 fd ff ff 8b e5 5d c2 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}