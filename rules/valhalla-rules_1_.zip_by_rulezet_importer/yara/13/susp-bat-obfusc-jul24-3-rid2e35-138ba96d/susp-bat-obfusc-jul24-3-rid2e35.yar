rule SUSP_BAT_OBFUSC_Jul24_3_RID2E35 : DEMO OBFUS SCRIPT SUSP T1027 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12 11:04:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, OBFUS, SCRIPT, SUSP, T1027"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "% \\\\%" 
      $s2 = { 3D ?? 26 26 73 65 74 20 } 
   condition: 
      filesize < 300KB and all of them
}