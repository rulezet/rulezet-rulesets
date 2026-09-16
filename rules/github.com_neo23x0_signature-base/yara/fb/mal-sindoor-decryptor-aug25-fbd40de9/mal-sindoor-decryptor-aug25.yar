rule MAL_Sindoor_Decryptor_Aug25 {
   meta:
      description = "Detects AES decryptor used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 80
      reference = "Internal Research"
      hash = "9a1adb50bb08f5a28160802c8f315749b15c9009f25aa6718c7752471db3bb4b"
   strings:
      $s1 = "Go build"
      $s2 = "main.rc4EncryptDecrypt"
      $s3 = "main.processFile"
      $s4 = "main.deriveKeyAES"
      $s5 = "use RC4 instead of AES"
   condition:
      filesize < 100MB
      and (
         uint16(0) == 0x5a4d          or uint32be(0) == 0x7f454c46           or (uint32be(0) == 0xcafebabe and uint32be(4) < 0x20)           or uint32(0) == 0xfeedface           or uint32(0) == 0xfeedfacf        )
      and all of them
}