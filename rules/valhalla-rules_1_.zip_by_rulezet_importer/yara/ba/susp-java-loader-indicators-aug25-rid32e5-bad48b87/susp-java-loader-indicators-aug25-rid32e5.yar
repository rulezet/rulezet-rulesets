rule SUSP_JAVA_Loader_Indicators_Aug25_RID32E5 : DEMO FILE SUSP T1203 T1566_001 {
   meta:
      description = "Detects indicators of a Java loader used in phishing campaigns"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07 14:24:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c4cf746fce283878dde567e5457a8ebdbb7ff3414be46569ecdd57338bd96fa1"
      tags = "DEMO, FILE, SUSP, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Loader.classPK" ascii fullword
      $s2 = "stubPK" ascii
      $s3 = "META-INF/MANIFEST.MFPK" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 500KB and $s1 in ( filesize - 224 .. filesize ) and $s2 in ( filesize - 224 .. filesize ) and $s3 in ( filesize - 224 .. filesize )
}