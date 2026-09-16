rule MAL_Katz_Stealer_May25 {
   meta:
      description = "Detects Katz stealer"
      author = "MalGamy (Nextron Systems)"
      date = "2025-05-16"
      reference = "Internal Research"
      hash = "fdc86a5b3d7df37a72c3272836f743747c47bfbc538f05af9ecf78547fa2e789"
      hash = "d92bb6e47cb0a0bdbb51403528ccfe643a9329476af53b5a729f04a4d2139647"
      score = 80
   strings:
      $s1 = "Motherboard Product: %s" ascii
      $s2 = "cmd.exe /c %s" ascii
      $s3 = "reg export \"%s\" \"%s\" /y" ascii
      $s4 = ").request({ hostname: '" ascii
      $s5 = "Type: Removable"
      $s6 = "%s\\Microsoft\\Windows Live Mail" ascii
   condition:
      uint16(0) == 0x5a4d
      and filesize < 300KB
      and 4 of them
}