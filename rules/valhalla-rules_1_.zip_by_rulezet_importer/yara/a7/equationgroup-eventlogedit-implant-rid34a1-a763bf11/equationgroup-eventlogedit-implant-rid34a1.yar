rule EquationGroup_EventLogEdit_Implant_RID34A1 : APT DEMO EXE FILE T1543_003 {
   meta:
      description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:38:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"
      tags = "APT, DEMO, EXE, FILE, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
      $s2 = "Ntdll.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}