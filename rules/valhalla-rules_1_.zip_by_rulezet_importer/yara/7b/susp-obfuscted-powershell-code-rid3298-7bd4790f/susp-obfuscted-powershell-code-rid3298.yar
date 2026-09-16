rule SUSP_Obfuscted_PowerShell_Code_RID3298 : DEMO OBFUS SCRIPT SUSP T1059_001 {
   meta:
      description = "Detects obfuscated PowerShell Code"
      author = "Florian Roth"
      reference = "https://twitter.com/silv0123/status/1073072691584880640"
      date = "2018-12-13 14:11:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, OBFUS, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "').Invoke(" ascii
      $s2 = "(\"{1}{0}\"" ascii
      $s3 = "{0}\" -f" ascii
   condition: 
      #s1 > 11 and #s2 > 10 and #s3 > 10
}