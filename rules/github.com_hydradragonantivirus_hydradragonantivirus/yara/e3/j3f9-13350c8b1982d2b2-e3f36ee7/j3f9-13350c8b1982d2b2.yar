rule j3f9_13350c8b1982d2b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f9.13350c8b1982d2b2"
    cluster      = "j3f9.13350c8b1982d2b2"
    cluster_size = "53"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "genpack generickdz upatre"
    md5_hashes   = "['0259d8c78c45704839976d2dec471c44','0cdee72e2d72960e42f04c2a933eddab','969598af0d6a91621081a47f8addb5ce']"

  strings:
    $hex_string = { 06 09 2f b4 c2 11 4a 04 86 ab 5d 10 ce 20 9a 0f da 23 00 90 f0 eb df 2b e4 d1 01 91 64 c7 77 d5 5b c1 0b 41 60 64 d7 0f 61 89 c9 be 4f d8 49 31 42 36 1a dc 33 32 21 27 44 cb 15 7a ea 7e 95 1d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}