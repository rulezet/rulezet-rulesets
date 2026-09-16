rule EquationGroup_EquationDrug_mstcp32_RID3486 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file mstcp32.sys"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:34:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mstcp32.sys" fullword wide
      $s2 = "p32.sys" fullword ascii
      $s3 = "\\Registry\\User\\CurrentUser\\" wide
      $s4 = "\\DosDevices\\%ws" wide
      $s5 = "\\Device\\%ws_%ws" wide
      $s6 = "sys\\mstcp32.dbg" fullword ascii
      $s7 = "%ws%03d%ws%wZ" fullword wide
      $s8 = "TCP/IP driver" fullword wide
      $s9 = "\\Device\\%ws" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 7 of them ) or ( all of them )
}