rule k26bb_632950b191e72336 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.632950b191e72336"
    cluster         = "k26bb.632950b191e72336"
    cluster_size    = "270"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "conduit riskware malicious"
    md5_hashes      = "['7c254dd120ad50fc9d36060bce44712878b9799a','7cb8f922e268ad5ae2dd0c87712976f9b93c583c','86560479ca43330c223f3c484f56e4e8073d9f47']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.632950b191e72336"

  strings:
    $hex_string = { 86 31 eb 69 90 9e 0d 88 e8 1b b6 d6 81 a8 f0 8a d9 e0 e3 41 5e 47 e5 97 48 1d a3 1c 64 db fb ae f6 22 8d cb d2 79 c9 67 fc 8c 34 ff 3e 98 a0 e4 49 5d 6c 35 70 39 21 06 30 72 50 26 2a fd 4c c4 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}