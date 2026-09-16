rule PowerShell_ISESteroids_Obfuscation_RID347F : DEMO OBFUS SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects PowerShell ISESteroids obfuscation"
      author = "Florian Roth"
      reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
      date = "2017-06-23 15:33:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, OBFUS, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/\\/===\\__" ascii
      $x2 = "${__/\\/==" ascii
      $x3 = "Catch { }" fullword ascii
      $x4 = "\\_/=} ${_" ascii
   condition: 
      2 of them
}