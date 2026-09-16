rule SUSP_JAVA_Class_Allatori_Obfuscator_Aug25 {
   meta:
      description = "Detects a relatively small Java class file obfuscated by Allatori Obfuscator"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 50
      hash1 = "0a7fddd91b332c8daee2c0727b884fc92cfaede02883dbad75f7efc299e884e3"
   strings:
      $x1 = "Obfuscation by Allatori Obfuscator" ascii fullword
   condition:
      uint16(0) == 0x4b50
      and filesize < 500KB
      and $x1
}