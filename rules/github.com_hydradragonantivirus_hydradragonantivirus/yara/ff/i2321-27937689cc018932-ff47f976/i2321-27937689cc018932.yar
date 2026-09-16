rule i2321_27937689cc018932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.27937689cc018932"
    cluster      = "i2321.27937689cc018932"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['1a2785bf721a0057da030313713aaaa1','1e0efffc785e7637aa3c412568ac16a5','cdb00b8e4ac18737030aa7161adb7509']"

  strings:
    $hex_string = { 2f 6f 8b 0d c6 35 77 c7 d8 6b db 62 87 63 ec 50 8c 5d da 16 ab 0c 36 df a3 af 6c 8b 7d 3b c6 72 fd 1f fe fe 1f 0a f9 62 bd 7c 74 71 b1 54 9d 2b 84 c9 d1 b1 c2 d1 fc 17 87 e6 2a 95 f8 96 3e 56 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}