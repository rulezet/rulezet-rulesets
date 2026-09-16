rule EquationGroup_PC_Level4_flav_dll_x64_RID34C5 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_dll_x64"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:44:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wship.dll" fullword wide
      $s2 = "   IP:      " fullword ascii
      $s3 = "\\\\.\\%hs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}