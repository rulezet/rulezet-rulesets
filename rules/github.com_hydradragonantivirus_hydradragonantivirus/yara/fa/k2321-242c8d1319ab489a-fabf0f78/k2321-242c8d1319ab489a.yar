rule k2321_242c8d1319ab489a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.242c8d1319ab489a"
    cluster      = "k2321.242c8d1319ab489a"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod kazy trojandropper"
    md5_hashes   = "['007ef61538a105dfc2801163006a50ef','17481c1c5a321c339b3ce05d2b0376c5','604683471158a52464242642772ccb59']"

  strings:
    $hex_string = { c7 b3 b6 17 8a e9 0e eb 34 15 e5 cd 25 87 9b ad 42 9e f2 04 fc 84 36 5d 78 03 9f 1e 4d 49 81 1f 61 d3 cf fd b2 8d 6c 7e ba e8 79 3e 20 ff 77 75 48 d7 fe 80 2d df 1d 74 9d 14 7a fb ee 99 02 96 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}