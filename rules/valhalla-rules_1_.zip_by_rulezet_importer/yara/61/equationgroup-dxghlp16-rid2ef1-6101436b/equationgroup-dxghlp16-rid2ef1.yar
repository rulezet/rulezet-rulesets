rule EquationGroup_DXGHLP16_RID2EF1 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file DXGHLP16.SYS"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 11:36:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "DXGHLP16.SYS" fullword wide
      $s2 = "P16.SYS" fullword ascii
      $s3 = "\\Registry\\User\\CurrentUser\\" wide
      $s4 = "\\DosDevices\\%ws" wide
      $s5 = "\\Device\\%ws_%ws" wide
      $s6 = "ct@SYS\\DXGHLP16.dbg" fullword ascii
      $s7 = "%ws%03d%ws%wZ" fullword wide
      $s8 = "TCP/IP driver" fullword wide
      $s9 = "\\Device\\%ws" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}