rule HKTL_EDR_Freeze_Sep25_2_RID2EBD : DEMO EXE HKTL {
   meta:
      description = "Detects EDR-Freeze hacktool"
      author = "Florian Roth"
      reference = "https://github.com/TwoSevenOneT/EDR-Freeze"
      date = "2025-09-30 11:27:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "193ca17f574fa5e23866560170425f83696f78e83dabd7e831dd7827a69283fd"
      hash2 = "36a17919a97732f1ddc31b421c6ebb0c535924f895d7caaff04a5da908c42f76"
      hash3 = "394b768bfd3506a9ee6b7bbe6f87c40fb23c28f7919a2a9eb333b27db635eafe"
      tags = "DEMO, EXE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "EDR-Freeze.exe <TargetPID> <SleepTime>" wide fullword
      $x2 = "Successfully created PPL process with PID:" wide fullword
      $x3 = "\\EDR-Freeze.pdb" ascii
      $sa1 = "C:\\Windows\\System32\\WerFaultSecure.exe" wide fullword
      $sa2 = "Failed to create dump files: " wide fullword
      $sb1 = " /encfile" wide fullword
      $sb2 = " /pid" wide fullword
      $sb3 = " /tid" wide fullword
      $sb4 = " /cancel" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or all of ( $sa* ) or all of ( $sb* ) ) or 6 of them
}