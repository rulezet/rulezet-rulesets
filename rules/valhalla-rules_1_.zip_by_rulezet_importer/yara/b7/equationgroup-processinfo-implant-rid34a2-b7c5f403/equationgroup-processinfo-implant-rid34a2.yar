rule EquationGroup_processinfo_Implant_RID34A2 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file processinfo_Implant.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "aadfa0b1aec4456b10e4fb82f5cfa918dbf4e87d19a02bcc576ac499dda0fb68"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "hZwOpenProcessToken" fullword ascii
      $s2 = "hNtQueryInformationProcess" fullword ascii
      $s3 = "No mapping" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}