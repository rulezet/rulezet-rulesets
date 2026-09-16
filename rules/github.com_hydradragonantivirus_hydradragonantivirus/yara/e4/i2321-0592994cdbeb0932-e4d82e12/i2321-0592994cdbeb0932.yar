rule i2321_0592994cdbeb0932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.0592994cdbeb0932"
    cluster      = "i2321.0592994cdbeb0932"
    cluster_size = "28"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke razy"
    md5_hashes   = "['0dd55583debdabdbc017383b3cda056d','1183031f7620c207930847d11041686b','7fc4157882bdbb93aefbc59988793cf5']"

  strings:
    $hex_string = { f7 57 66 cf da a1 eb b3 4f 45 7c 2b 6c 8f 8b d9 86 98 6d 75 76 f5 a9 b4 75 c7 ec b7 63 03 1f aa 9e cb ef c6 a6 fc ee be b9 a3 f6 e6 c0 8a 4a b6 ee 81 28 58 95 37 4d 67 1e dd f9 e5 87 5f 6e c9 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}