rule PowerShell_JAB_B64_RID2D4D : DEMO FILE SCRIPT SUSP T1059_001 T1132_001 {
   meta:
      description = "Detects base464 encoded $ sign at the beginning of a string"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
      date = "2018-04-02 10:26:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-01-14"
      tags = "DEMO, FILE, SCRIPT, SUSP, T1059_001, T1132_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "('JAB" ascii wide
      $s2 = "powershell" nocase
   condition: 
      filesize < 30KB and all of them
}