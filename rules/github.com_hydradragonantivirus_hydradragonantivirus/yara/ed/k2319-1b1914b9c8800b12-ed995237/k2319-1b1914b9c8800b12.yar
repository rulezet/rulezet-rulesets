rule k2319_1b1914b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1b1914b9c8800b12"
    cluster         = "k2319.1b1914b9c8800b12"
    cluster_size    = "21"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script adinject"
    md5_hashes      = "['ca83d40c0d95571e3fcbe24de4bab0b88c1f2819','fb1de989247cf50c87aabb706492d19db4298e05','68eab1295b2b459ca24b6948c9191d55576c50bf']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1b1914b9c8800b12"

  strings:
    $hex_string = "3)?(0x149,119):(10.,27.3E1)))break};var B6y4={'Y1i':function(n,k"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}