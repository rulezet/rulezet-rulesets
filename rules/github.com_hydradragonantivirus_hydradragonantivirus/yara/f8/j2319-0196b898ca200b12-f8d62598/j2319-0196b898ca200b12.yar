rule j2319_0196b898ca200b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2319.0196b898ca200b12"
    cluster      = "j2319.0196b898ca200b12"
    cluster_size = "7"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "redirector fakejquery html"
    md5_hashes   = "['51e350df084330aee04e3803a079912e','90214fe7969eefe6b3be8c90027792b6','e822dc0124fd85ffa98981975dc4c22f']"

  strings:
    $hex_string = "+'/script>');}</script>\r\n</head>\n<body class=\"html front not-log"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}