rule k2321_2318d64bdfa30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2318d64bdfa30912"
    cluster      = "k2321.2318d64bdfa30912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jtlp kryptik hupigon"
    md5_hashes   = "['60ad185d2bb16cc35da5c89d166abfae','715839ea49a0dedf276e78f4f0f5a7d9','ec700adb43ac4e7d872fbaabcfdcb136']"

  strings:
    $hex_string = { 04 bd d4 3d e4 92 4b 79 62 06 ce 0c 1a fa 69 e6 5e df 07 96 a9 dc ca 2c fc 8d 74 6e 4c b9 32 1c a8 8a 2e 3a 67 63 d6 ad c4 9b b1 a6 91 33 2f ed de 0d cd 57 f9 21 51 47 4f f1 14 1c 39 6f fb 8c }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}