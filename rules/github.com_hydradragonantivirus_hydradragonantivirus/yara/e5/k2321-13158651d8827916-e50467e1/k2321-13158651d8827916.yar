rule k2321_13158651d8827916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.13158651d8827916"
    cluster      = "k2321.13158651d8827916"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['4a922c6b2dd025d7f23b5b8341472b2d','c392ebdb2107596c9a46bc5fc8df966c','fe0d51f2a7793d068d368a21c8909cca']"

  strings:
    $hex_string = { 54 39 1b 08 3b 4f 7e 2d e7 b7 95 df c3 67 50 03 4b 6d 52 09 83 05 69 65 7c a6 20 bd f0 9c 56 9b e6 2b e4 5b a8 6f 84 0a 0d b1 29 67 d2 c5 be cf a4 cd e5 f2 4c 6a 2e 68 81 8c 8d fc 6b 0f d6 13 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}