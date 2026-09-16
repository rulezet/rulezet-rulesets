rule k3e9_63b4b363d0969b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d0969b16"
    cluster      = "k3e9.63b4b363d0969b16"
    cluster_size = "16"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob classic"
    md5_hashes   = "['012f9557cb7667fbabfbc361ae790592','0a3508453d5c6e1d7043f8f0d73d2623','e0153ad27adefa7c02fafe5c3758db61']"

  strings:
    $hex_string = { 4d fc 8b 09 89 08 8a 0b 88 48 04 83 45 fc 04 46 43 3b f7 7c b7 33 db a1 a0 87 00 01 8d 34 d8 83 3e ff 75 4d 85 db c6 46 04 81 75 05 6a f6 58 eb 0a 8b c3 48 f7 d8 1b c0 83 c0 f5 50 ff 15 84 10 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}