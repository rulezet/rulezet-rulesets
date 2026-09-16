rule PlugX_J16_Gen2_RID2BBC : DEMO EXE FILE MAL plugx {
   meta:
      description = "Detects PlugX Malware Samples from June 2016"
      author = "Florian Roth"
      reference = "MISP 3954"
      date = "2016-06-08 09:19:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5dff1e086c5191a0bd7ac13466b7a81a87e99e51968df2f32570eb031c537ab4"
      hash2 = "710326804b78ccd2782abc16354e389f0e36ba9474ebdced17337a13082ac12f"
      tags = "DEMO, EXE, FILE, MAL, plugx"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "XPlugKeyLogger.cpp" fullword ascii
      $s2 = "XPlugProcess.cpp" fullword ascii
      $s4 = "XPlgLoader.cpp" fullword ascii
      $s5 = "XPlugPortMap.cpp" fullword ascii
      $s8 = "XPlugShell.cpp" fullword ascii
      $s11 = "file: %s, line: %d, error: [%d]%s" fullword ascii
      $s12 = "XInstall.cpp" fullword ascii
      $s13 = "XPlugTelnet.cpp" fullword ascii
      $s14 = "XInstallUAC.cpp" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( 2 of ( $s* ) ) ) or ( 5 of them )
}