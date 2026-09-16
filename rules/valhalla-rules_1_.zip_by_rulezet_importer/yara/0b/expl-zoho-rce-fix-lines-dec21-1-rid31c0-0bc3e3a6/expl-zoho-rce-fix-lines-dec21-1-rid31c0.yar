rule EXPL_Zoho_RCE_Fix_Lines_Dec21_1_RID31C0 : DEMO EXPLOIT {
   meta:
      description = "Detects lines in log lines of Zoho products that indicate RCE fixes (silent removal of evidence)"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1467784104930385923"
      date = "2021-12-06 13:35:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "RCEF=" 
      $sa1 = "\"attackStatus\"\\:\"active\"" 
      $sa2 = "\"attackStatus\":\"active\"" 
      $sd1 = "deletedCount" 
      $sd_fp1 = "\"deletedCount\"\\:0" 
      $sd_fp2 = "\"deletedCount\":0" 
   condition: 
      filesize < 6MB and $s1 and ( 1 of ( $sa* ) or ( $sd1 and not 1 of ( $sd_fp* ) ) )
}