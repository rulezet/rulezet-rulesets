rule MAL_Sindoor_Downloader_Aug25 {
   meta:
      description = "Detects Sindoor downloader related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 80
      reference = "Internal Research"
      hash = "38b6b93a536cbab5c289fe542656d8817d7c1217ad75c7f367b15c65d96a21d4"
   strings:
      $s1 = "Go build"
      $s2 = "main.downloadFile.deferwrap"
      $s3 = "main.decrypt"
      $s4 = "main.HiddenHome"
      $s5 = "main.RealCheck"
   condition:
      filesize < 100MB
      and (
         uint16(0) == 0x5a4d          or uint32be(0) == 0x7f454c46           or (uint32be(0) == 0xcafebabe and uint32be(4) < 0x20)           or uint32(0) == 0xfeedface           or uint32(0) == 0xfeedfacf        )
      and all of them
}