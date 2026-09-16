rule SUSP_EXPL_JAR_Indicators_Dec24_RID3170 : DEMO EXPLOIT FILE SUSP {
   meta:
      description = "Detects characteristics of JAR files used during Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10 13:22:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TLS v3 " ascii
      $s2 = "java/util/Base64$Decoder" ascii
      $s3 = "AES/CBC/NoPadding" ascii
      $s4 = "getenv" ascii
      $s5 = "ava/util/zip/ZipInputStream" ascii
   condition: 
      uint16 ( 0 ) == 0xfeca and filesize < 20KB and all of them
}