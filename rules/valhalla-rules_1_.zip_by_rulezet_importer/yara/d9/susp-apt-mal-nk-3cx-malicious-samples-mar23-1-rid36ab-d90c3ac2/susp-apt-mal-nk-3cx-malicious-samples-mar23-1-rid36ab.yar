rule SUSP_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1_RID36AB : APT DEMO MAL NK SUSP {
   meta:
      description = "Detects marker found in malicious DLLs related to 3CX compromise"
      author = "X__Junior, Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29 17:05:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-04-20"
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
      hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"
      tags = "APT, DEMO, MAL, NK, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $opx1 = { 41 80 7C 00 FD FE 75 ?? 41 80 7C 00 FE ED 75 ?? 41 80 7C 00 FF FA 75 ?? 41 80 3C 00 CE } 
      $opx2 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE } 
   condition: 
      1 of them
}