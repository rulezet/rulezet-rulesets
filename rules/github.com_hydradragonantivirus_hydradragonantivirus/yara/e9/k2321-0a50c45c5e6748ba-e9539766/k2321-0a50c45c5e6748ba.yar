rule k2321_0a50c45c5e6748ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0a50c45c5e6748ba"
    cluster      = "k2321.0a50c45c5e6748ba"
    cluster_size = "30"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['1032257b6e8d8f7dd7475fc1e2dffb3d','15cd95bf68dbd855644d084ebb834dae','943d0e6f60b593434b9495e09f3b403b']"

  strings:
    $hex_string = { cc e5 f1 71 8e 1e bc 3c 93 73 e9 36 11 2a 2f 50 74 34 a6 25 37 96 10 d1 66 a5 1a 91 ed b2 d9 28 14 00 ba 6a 69 b7 5a a1 9f bf 97 7f 9d 40 ac d0 f2 ef 2e bd 61 82 ea 39 eb 70 03 72 30 46 31 88 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}