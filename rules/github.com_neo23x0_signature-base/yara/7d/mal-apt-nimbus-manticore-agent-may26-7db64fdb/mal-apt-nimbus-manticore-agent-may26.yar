rule MAL_APT_Nimbus_Manticore_Agent_May26 {
   meta:
      description = "Detects Nimbus Manticore (UNC1549) agent implant featuring data exfiltration and remote control."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-28"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "dfa1e3137a032ee8561a1cd5e1a0f71a10bebb36aef7c336c878638a9c1239ee"
      score = 80
   strings:
      $a1 = "Chrome/146.0.0.0 Safari/537.36" wide
      $a2 = ".azurewebsites.net" wide

      $s1 = "/agent/poll?token=" wide fullword
      $s2 = "/agent/init" wide fullword
      $s3 = "/agent/result" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and 1 of ($a*) 
      and 1 of ($s*)
      or 3 of them
}