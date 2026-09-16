rule j3eb_400153a202000000 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3eb.400153a202000000"
    cluster      = "j3eb.400153a202000000"
    cluster_size = "42"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "crypt fjin rozena"
    md5_hashes   = "['0864d5599e930e47d2d9e5ceb2097e88','0965fd4919f9fdc6081073af54590d4d','60e2ddfcefb2d5a011beece43a40b352']"

  strings:
    $hex_string = { 00 49 c7 c0 00 30 00 00 48 c7 c2 00 10 00 00 48 33 c9 e8 27 10 00 00 48 c7 c1 00 10 00 00 48 be 41 10 00 40 01 00 00 00 48 8b f8 f3 a4 ff d0 48 33 c9 e8 01 10 00 00 50 41 59 4c 4f 41 44 3a 00 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}