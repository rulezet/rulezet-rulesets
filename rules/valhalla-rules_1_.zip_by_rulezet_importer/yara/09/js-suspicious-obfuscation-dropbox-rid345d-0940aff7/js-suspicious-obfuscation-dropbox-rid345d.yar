rule JS_Suspicious_Obfuscation_Dropbox_RID345D : DEMO OBFUS SCRIPT T1059 T1059_001 T1059_007 {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19 15:27:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, OBFUS, SCRIPT, T1059, T1059_001, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\"" 
      $x2 = "script:https://www.dropbox.com" ascii
   condition: 
      2 of them
}