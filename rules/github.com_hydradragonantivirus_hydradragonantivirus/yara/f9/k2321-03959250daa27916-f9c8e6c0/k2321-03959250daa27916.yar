rule k2321_03959250daa27916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.03959250daa27916"
    cluster      = "k2321.03959250daa27916"
    cluster_size = "3"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['26c355d76ad08cc9e8309eefc633c640','4d7f8050e3710ea8e7dfd4a24346e891','c5d38b179f3767eea21da23f3f006d56']"

  strings:
    $hex_string = { b8 e2 d8 ed 13 9b 94 4a dc d3 77 25 1e af 54 7a 20 12 07 93 8a 63 7c f8 6e 25 2b 43 7d 09 0c 5e 37 b0 2a 0e 6f 80 86 3a 8f ee b7 bc 46 fd 85 7f c6 56 b2 d6 b5 d5 cd 7e 3d 5c ad 1c 2e ba 9d 70 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}