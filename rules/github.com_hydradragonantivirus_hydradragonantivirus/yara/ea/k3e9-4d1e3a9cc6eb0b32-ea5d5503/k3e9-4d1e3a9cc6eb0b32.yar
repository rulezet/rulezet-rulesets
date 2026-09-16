rule k3e9_4d1e3a9cc6eb0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4d1e3a9cc6eb0b32"
    cluster      = "k3e9.4d1e3a9cc6eb0b32"
    cluster_size = "22"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol servstart networkworm"
    md5_hashes   = "['099065cc52567cb84b8356fc5ff015ed','17ff5d88219aefef715bf9636be5903d','dba9c5ca15820612464dbd7934e2cbdc']"

  strings:
    $hex_string = { 14 40 3b c2 89 44 24 10 7c b0 5f 5e 5d b8 01 00 00 00 5b 81 c4 0c 01 00 00 c3 8d 74 1c 18 83 c9 ff 8b fe 33 c0 f2 ae f7 d1 49 8d 7c 2b 01 88 0c 2b 0f be c9 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}