rule WiltedTulip_Windows_UM_Task_RID31C5 : APT DEMO T1053 T1053_005 T1218_011 {
   meta:
      description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 13:36:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"
      tags = "APT, DEMO, T1053, T1053_005, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $r1 = "<Command>C:\\Windows\\syswow64\\rundll32.exe</Command>" fullword wide
      $p1 = "<Arguments>\"C:\\Users\\public\\" wide
      $c1 = "svchost64.swp\",checkUpdate" wide ascii
      $c2 = "svchost64.swp,checkUpdate" wide ascii
   condition: 
      ( $r1 and $p1 ) or 1 of ( $c* )
}