rule MAL_IcedID_Fake_GZIP_Bokbot_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-20"
      description = "Detects fake gzip provided by CC"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "538d84d8-aff2-571c-ba60-102f18262434"
   strings:
      $gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}
   condition:
      $gzip at 0
}