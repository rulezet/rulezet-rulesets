rule k3e9_1192bc99efa10932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1192bc99efa10932"
    cluster      = "k3e9.1192bc99efa10932"
    cluster_size = "3258"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma malicious"
    md5_hashes   = "['00284bc203142b6b6ac8d69f67b06afd','009a8a5edbf1e3656338221f3ac017c6','0388941b5342ca32b56ca10598ec2174']"

  strings:
    $hex_string = { 04 d9 82 54 77 9a 2a 14 8b 86 96 21 d7 a9 d3 aa 25 5d a8 f3 a2 25 5b c4 d0 cc 37 98 2b 39 57 02 be c7 e4 a1 48 9f 70 4b 24 17 ae c2 ce 9b 0b 80 c5 55 7a 06 56 fc 8a b3 e5 9e 09 79 e7 d8 eb b4 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}