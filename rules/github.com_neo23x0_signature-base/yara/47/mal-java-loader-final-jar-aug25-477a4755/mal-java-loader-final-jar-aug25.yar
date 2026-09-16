rule MAL_JAVA_Loader_Final_Jar_Aug25 {
   meta:
      description = "Detects a final Java loader JAR file used in phishing campaigns"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 85
      hash1 = "0a7fddd91b332c8daee2c0727b884fc92cfaede02883dbad75f7efc299e884e3"
   strings:
      $s1 = "Obfuscation by Allatori Obfuscator" ascii fullword
      $s2 = "MANIFEST.MFM" ascii fullword
      $s3 = "GetCpu.classPK" ascii fullword
      $s4 = "extra/spreader" ascii fullword
   condition:
      all of them
}