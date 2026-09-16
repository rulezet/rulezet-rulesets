rule MAL_JS_EFile_Apr23_1_RID2D82 : DEMO MAL T1059_007 {
   meta:
      description = "Detects JavaScript malware used in eFile compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/Ax_Sharma/status/1643178696084271104/photo/1"
      date = "2023-04-06 10:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "let payload_chrome = " 
      $s2 = "else if (agent.indexOf(\"firefox" 
   condition: 
      all of them
}