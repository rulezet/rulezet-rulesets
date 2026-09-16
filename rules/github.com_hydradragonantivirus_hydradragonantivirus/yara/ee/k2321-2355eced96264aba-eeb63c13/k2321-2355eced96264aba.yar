rule k2321_2355eced96264aba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2355eced96264aba"
    cluster      = "k2321.2355eced96264aba"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['23fd8d6e6f1b3c2ec192e11168f45431','6c104696d0c004586dd06f33ce3332df','b93f402e9ac450e3897dd87473e873c1']"

  strings:
    $hex_string = { e1 8c ec a2 71 f9 d2 84 5c f4 9a f4 e4 5c 72 4d 62 ca c4 12 e9 f0 dc e2 69 e3 f2 a4 43 4b a6 65 e6 4e 49 1f 1e 1b a9 c6 29 3c 68 50 52 2c 57 77 ea 3e 90 b7 35 1d f7 14 91 cf 80 55 88 e7 01 d6 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}