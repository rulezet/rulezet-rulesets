rule MAL_Korplug_FAST_RID2CBB : DEMO EXE FILE MAL T1218_011 {
   meta:
      description = "Rule to detect Korplug/PlugX FAST variant"
      author = "Florian Roth"
      reference = "-"
      date = "2015-08-20 10:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%s\\rundll32.exe \"%s\", ShadowPlay" fullword ascii
      $a1 = "ShadowPlay" fullword ascii
      $s1 = "%s\\rundll32.exe \"%s\"," fullword ascii
      $s2 = "nvdisps.dll" fullword ascii
      $s3 = "%snvdisps.dll" fullword ascii
      $s4 = "\\winhlp32.exe" ascii
      $s5 = "nvdisps_user.dat" fullword ascii
      $s6 = "%snvdisps_user.dat" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( $x1 or ( $a1 and 1 of ( $s* ) ) or 4 of ( $s* ) )
}