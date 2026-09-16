rule SUSP_BAT_OBFUSC_Jul24_1_RID2E33 : DEMO FILE OBFUS SCRIPT SUSP T1027 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12 11:04:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, OBFUS, SCRIPT, SUSP, T1027"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "&&set " 
   condition: 
      filesize < 300KB and uint32 ( 0 ) == 0x20746573 and $s1 in ( 0 .. 32 )
}