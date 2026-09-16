rule MAL_MuddyWater_DroppedTask_Jun18_1_RID3395 : APT DEMO FILE G0069 MAL {
   meta:
      description = "Detects a dropped Windows task as used by MudyWater in June 2018"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/719c94eb-0a00-47cc-b583-ad4f9e25ebdb"
      date = "2018-06-12 14:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ecc2e1817f655ece2bde39b7d6633f4f586093047ec5697a1fab6adc7e1da54"
      tags = "APT, DEMO, FILE, G0069, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%11%\\scrobj.dll,NI,c:" wide
      $s1 = "AppAct = \"SOFTWARE\\Microsoft\\Connection Manager\"" fullword wide
      $s2 = "[DefenderService]" fullword wide
      $s3 = "UnRegisterOCXs=EventManager" fullword wide
      $s4 = "ShortSvcName=\" \"" fullword wide
   condition: 
      uint16 ( 0 ) == 0xfeff and filesize < 1KB and ( 1 of ( $x* ) or 3 of them )
}