rule j3f7_3923b7b49ec30932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.3923b7b49ec30932"
    cluster      = "j3f7.3923b7b49ec30932"
    cluster_size = "6"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe html script"
    md5_hashes   = "['2b974269c95094ba66fcfcd7aa8f300b','604af5fe7f4eb6801c318c84dff57a4d','f39dc444976da4a14b50ef0880250af9']"

  strings:
    $hex_string = "id=\"v_mysql\" href=\"http://www.mysql.com/\" target=\"_blank\"></a>\n "

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}