rule SUSP_EXPL_JAR_Indicators_Dec24 {
   meta:
      description = "Detects characteristics of JAR files used during Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "4e8f6aa8-9efd-5fcf-b795-5042d4ba1708"
   strings:
      $s1 = "TLS v3 " ascii
      $s2 = "java/util/Base64$Decoder" ascii
      $s3 = "AES/CBC/NoPadding" ascii
      $s4 = "getenv" ascii
      $s5 = "ava/util/zip/ZipInputStream" ascii
   condition:
      uint16(0) == 0xfeca
      and filesize < 20KB
      and all of them
}