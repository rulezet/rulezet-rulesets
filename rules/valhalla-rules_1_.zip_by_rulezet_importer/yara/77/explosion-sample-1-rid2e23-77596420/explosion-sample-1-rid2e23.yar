rule Explosion_Sample_1_RID2E23 : APT DEMO FILE G0123 MIDDLE_EAST T1112 {
   meta:
      description = "Explosion/Explosive Malware - Volatile Cedar APT"
      author = "Florian Roth"
      reference = "https://securelist.com/sinkholing-volatile-cedar-dga-infrastructure/69421/"
      date = "2015-04-03 11:01:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, G0123, MIDDLE_EAST, T1112"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
      $s9 = "WinAutologon From Winlogon Reg" fullword ascii
      $s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
      $s11 = "IE:Password-Protected sites" fullword ascii
      $s12 = "\\his.sys" ascii
      $s13 = "HTTP Password" fullword ascii
      $s14 = "\\data.sys" ascii
      $s15 = "EL$_RasDefaultCredentials#0" fullword wide
      $s17 = "Office Outlook HTTP" fullword ascii
      $s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5A4D and all of them
}