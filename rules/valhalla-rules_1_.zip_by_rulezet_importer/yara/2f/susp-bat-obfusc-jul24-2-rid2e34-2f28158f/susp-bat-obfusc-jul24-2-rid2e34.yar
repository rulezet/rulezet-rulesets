rule SUSP_BAT_OBFUSC_Jul24_2_RID2E34 : DEMO FILE OBFUS SCRIPT SUSP T1027 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12 11:04:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, OBFUS, SCRIPT, SUSP, T1027"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "&&set " 
   condition: 
      filesize < 300KB and #s1 > 30 and uint16 ( filesize - 2 ) == 0x0a0d and uint8 ( filesize - 3 ) == 0x25
}