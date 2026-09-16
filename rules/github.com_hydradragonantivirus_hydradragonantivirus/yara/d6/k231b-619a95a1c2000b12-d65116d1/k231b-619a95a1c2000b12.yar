rule k231b_619a95a1c2000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k231b.619a95a1c2000b12"
    cluster      = "k231b.619a95a1c2000b12"
    cluster_size = "4"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "redirector fakejquery script"
    md5_hashes   = "['3222ac5daabcc33c7a4933250590a962','4b77602c22c62b48630db0ca373c294f','6bb5ecfa55d56a190bdb0bb84d2ae74e']"

  strings:
    $hex_string = { 3c 64 69 76 20 63 6c 61 73 73 3d 22 77 69 64 67 65 74 2d 74 6f 70 22 3e 3c 68 34 3e 5a 47 c5 81 4f c5 9a 20 5a 57 49 45 52 5a c4 98 20 57 20 50 4f 54 52 5a 45 42 49 45 20 36 30 34 20 35 31 32 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}