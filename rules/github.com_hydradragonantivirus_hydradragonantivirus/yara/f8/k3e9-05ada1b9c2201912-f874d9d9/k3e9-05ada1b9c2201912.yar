rule k3e9_05ada1b9c2201912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.05ada1b9c2201912"
    cluster      = "k3e9.05ada1b9c2201912"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "floxif pioneer cccee"
    md5_hashes   = "['0ce6dec0e2e3f451fc9176070b4135af','6029ca57d8a48f534d59de173d1ba790','ff1375a8e4c4876f74dfaa363a9de7ce']"

  strings:
    $hex_string = { a2 95 50 09 05 31 c1 c8 3c f7 62 19 d7 d9 c5 5d bb be ab d5 c9 c6 25 a0 e1 6e e0 db d6 9d 5f fe 5c 13 6f 3f b4 ae ba c7 90 2d 55 90 29 f3 49 46 34 35 4f 88 29 42 d2 1c b5 56 48 41 e9 d0 44 f5 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}