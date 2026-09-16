rule Explosion_Sample_2_RID2E24 : APT DEMO FILE G0123 MIDDLE_EAST {
   meta:
      description = "Explosion/Explosive Malware - Volatile Cedar APT"
      author = "Florian Roth"
      reference = "https://securelist.com/sinkholing-volatile-cedar-dga-infrastructure/69421/"
      date = "2015-04-03 11:01:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, G0123, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "serverhelp.dll" fullword wide
      $s1 = "Windows Help DLL" fullword wide
      $s5 = "SetWinHoK" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5A4D and all of them
}