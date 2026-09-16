rule n3f9_09118328daaf5912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f9.09118328daaf5912"
    cluster      = "n3f9.09118328daaf5912"
    cluster_size = "78"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "airadinstaller airinstaller bundler"
    md5_hashes   = "['09b3a829f804102766251d383c9320a8','146649c7479ee10d037fe99cb72eb5d5','5fad69b2a5c9284a267e4a67d2197f55']"

  strings:
    $hex_string = { de e3 40 0f 8e ac 74 3c 4b 53 fd 21 d5 15 12 fb c9 b6 b9 30 bd 01 8d 51 0f 85 88 c9 ec 00 eb d2 f0 8f 2f 45 64 6a 3a b6 c0 f9 e6 55 24 39 be d5 c8 cf ca b4 7e d0 9f 84 c9 80 e7 05 c3 66 65 fd }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}