rule EquationGroup_EquationDrug_Gen_1_RID33A4 : APT DEMO EXE FILE GEN {
   meta:
      description = "EquationGroup Malware"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:56:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "694be2698bcc5c7a1cce11f8ef65c1c96a883d14b98148c36b32888fb58b6a7e"
      hash2 = "73d1d55493886639c619e9f5e312daab93e4feeb74f24dbe51593842baac8d15"
      hash3 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"
      tags = "APT, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Injection Lib -  GetProcAddress failed on Kernel32.DLL function" fullword wide
      $x2 = "Injection Lib -  JUMPUP failed to open requested process" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of ( $x* ) ) or ( all of them )
}