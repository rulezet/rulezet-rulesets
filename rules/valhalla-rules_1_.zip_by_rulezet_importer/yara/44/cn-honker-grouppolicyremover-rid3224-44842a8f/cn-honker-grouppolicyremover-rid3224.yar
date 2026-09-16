rule CN_Honker_GroupPolicyRemover_RID3224 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file GroupPolicyRemover.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:52:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GP_killer.EXE" fullword wide
      $s1 = "GP_killer Microsoft " fullword wide
      $s2 = "SHDeleteKeyA" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and all of them
}