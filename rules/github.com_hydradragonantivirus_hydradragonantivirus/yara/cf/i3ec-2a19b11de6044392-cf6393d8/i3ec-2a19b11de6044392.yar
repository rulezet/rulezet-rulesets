rule i3ec_2a19b11de6044392 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ec.2a19b11de6044392"
    cluster      = "i3ec.2a19b11de6044392"
    cluster_size = "290"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector infector malicious"
    md5_hashes   = "['00aa3e730899cb124880992b8921ab8f','013c0b7139f5e07314db453a036eabd5','084cc0236041cc7dabc7b04086bdeb59']"

  strings:
    $hex_string = { 06 00 00 00 31 d2 f7 f3 83 fa 04 77 20 8d b5 fc fd ff ff 31 c0 ac 85 d2 74 05 01 c6 4a eb f6 89 f3 5e 87 f3 5f 89 c1 f3 a4 87 f3 eb 02 5e 5f 59 49 85 c9 74 02 eb 83 8b 45 50 29 c7 c3 8d 85 21 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}