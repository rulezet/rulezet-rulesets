rule EquationGroup_nethide_Implant_RID32D8 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file nethide_Implant.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:22:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "b2daf9058fdc5e2affd5a409aebb90343ddde4239331d3de8edabeafdb3a48fa"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\dlcndi" fullword ascii
      $s2 = "s\\drivers\\" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 90KB and all of them )
}