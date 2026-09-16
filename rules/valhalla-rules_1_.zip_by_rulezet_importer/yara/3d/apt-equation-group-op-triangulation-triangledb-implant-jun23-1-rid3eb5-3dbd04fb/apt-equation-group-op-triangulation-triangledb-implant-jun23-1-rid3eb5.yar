rule APT_Equation_Group_Op_Triangulation_TriangleDB_Implant_Jun23_1_RID3EB5 : APT DEMO G0020 MACOS {
   meta:
      description = "Detects TriangleDB implant found being used in Operation Triangulation on iOS devices (maybe also used on macOS systems)"
      author = "Florian Roth"
      reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
      date = "2023-06-21 22:48:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0020, MACOS"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "unmungeHexString" ascii fullword
      $s2 = "CRPwrInfo" ascii fullword
      $s3 = "CRConfig" ascii fullword
      $s4 = "CRXConfigureDBServer" ascii fullword
   condition: 
      ( uint16 ( 0 ) == 0xfacf and filesize < 30MB and $s1 and 2 of them ) or all of them
}