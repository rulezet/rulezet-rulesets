rule EquationGroup_pwdump_Implant_RID3294 : APT DEMO EXE FILE T1003 {
   meta:
      description = "EquationGroup Malware - file pwdump_Implant.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:11:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "dfd5768a4825d1c7329c2e262fde27e2b3d9c810653585b058fcf9efa9815964"
      tags = "APT, DEMO, EXE, FILE, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s8 = ".?AVFeFinallySuccess@@" fullword ascii
      $s3 = "\\system32\\win32k.sys" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}