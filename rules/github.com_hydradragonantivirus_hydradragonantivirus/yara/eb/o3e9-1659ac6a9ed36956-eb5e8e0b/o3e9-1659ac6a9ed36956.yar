rule o3e9_1659ac6a9ed36956 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1659ac6a9ed36956"
    cluster      = "o3e9.1659ac6a9ed36956"
    cluster_size = "25"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0bad0581302ac9dfd996302fa9dcd3de','190047740289f0c65411fb2e1b2478f8','98ab4f396e21808e1387a9488b51e550']"

  strings:
    $hex_string = { cc a4 dd 22 0b cb 6c 8c d7 07 12 9c a3 b4 e2 98 ea 43 df eb b9 12 85 87 bd d1 04 13 16 e6 24 fc f3 5a 69 45 a3 3f 80 ce be 5b 56 40 b3 7f b8 95 e3 a0 c2 be 29 e4 9d 00 5b 34 24 74 c4 4e 46 26 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}