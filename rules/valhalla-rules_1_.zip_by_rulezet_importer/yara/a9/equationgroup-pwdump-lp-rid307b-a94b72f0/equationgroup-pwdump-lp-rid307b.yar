rule EquationGroup_pwdump_Lp_RID307B : APT DEMO EXE FILE T1003 {
   meta:
      description = "EquationGroup Malware - file pwdump_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 12:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"
      tags = "APT, DEMO, EXE, FILE, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "PWDUMP - - ERROR - -" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}