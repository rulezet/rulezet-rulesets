rule APT_DarkHydrus_Jul18_2_RID2EDA : APT DEMO EXE FILE G0079 MIDDLE_EAST {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 11:32:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"
      tags = "APT, DEMO, EXE, FILE, G0079, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "windir" fullword ascii
      $s6 = "temp.dll" fullword ascii
      $s7 = "libgcj-12.dll" fullword ascii
      $s8 = "%s\\System32\\%s" fullword ascii
      $s9 = "StartW" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them
}