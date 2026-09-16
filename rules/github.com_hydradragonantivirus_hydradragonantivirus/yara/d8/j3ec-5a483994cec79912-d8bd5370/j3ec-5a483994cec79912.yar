rule j3ec_5a483994cec79912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.5a483994cec79912"
    cluster      = "j3ec.5a483994cec79912"
    cluster_size = "13"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "crytex hublo geksone"
    md5_hashes   = "['206c1739d2c750c59a22743f33452dc6','478ea66039e65fe7e557b084de9b869a','f2976dd9edfaee2bd09e2637a3bc6dde']"

  strings:
    $hex_string = { 62 67 50 72 69 6e 74 00 00 62 00 4e 74 43 6c 6f 73 65 00 bf 00 4e 74 4f 70 65 6e 46 69 6c 65 00 00 6d 02 52 74 6c 49 6e 69 74 55 6e 69 63 6f 64 65 53 74 72 69 6e 67 00 00 6e 74 64 6c 6c 2e 64 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}