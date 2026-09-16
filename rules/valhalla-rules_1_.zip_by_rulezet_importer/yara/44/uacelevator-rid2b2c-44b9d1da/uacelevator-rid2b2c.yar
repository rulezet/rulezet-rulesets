rule UACElevator_RID2B2C : DEMO EXE FILE HKTL T1548_002 {
   meta:
      description = "UACElevator_RID2B2C bypassing UAC - file UACElevator_RID2B2C.exe"
      author = "Florian Roth"
      reference = "https://github.com/MalwareTech/UACElevator_RID2B2C"
      date = "2015-05-14 08:55:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, HKTL, T1548_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\UACElevator_RID2B2C.pdb" ascii
      $s1 = "%userprofile%\\Downloads\\dwmapi.dll" fullword ascii
      $s2 = "%windir%\\system32\\dwmapi.dll" fullword ascii
      $s3 = "Infection module: %s" fullword ascii
      $s4 = "Could not save module to %s" fullword ascii
      $s5 = "%s%s%p%s%ld%s%d%s" fullword ascii
      $s6 = "Stack area around _alloca memory reserved by this function is corrupted" fullword ascii
      $s7 = "Stack around the variable '" fullword ascii
      $s8 = "MSVCR120D.dll" fullword wide
      $s9 = "Address: 0x" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 172KB and ( $x1 or 8 of ( $s* ) )
}