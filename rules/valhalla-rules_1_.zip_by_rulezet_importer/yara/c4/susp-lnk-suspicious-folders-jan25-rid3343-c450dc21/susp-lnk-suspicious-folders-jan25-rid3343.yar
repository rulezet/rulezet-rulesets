rule SUSP_LNK_Suspicious_Folders_Jan25_RID3343 : DEMO FILE SUSP T1210 T1547_009 {
   meta:
      description = "Detects link files (.LNK) with suspicious folders mentioned in the target path"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-01-24 14:40:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-19"
      tags = "DEMO, FILE, SUSP, T1210, T1547_009"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "RECYCLER.BIN\\" wide
      $x2 = "Perflogs\\" wide
   condition: 
      uint16 ( 0 ) == 0x004c and 1 of them
}