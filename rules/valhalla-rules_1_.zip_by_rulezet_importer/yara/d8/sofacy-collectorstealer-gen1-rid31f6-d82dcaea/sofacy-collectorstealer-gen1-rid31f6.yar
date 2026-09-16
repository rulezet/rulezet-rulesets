rule Sofacy_CollectorStealer_Gen1_RID31F6 : APT DEMO EXE FILE G0007 GEN RUSSIA {
   meta:
      description = "Generic rule to detect Sofacy Malware Collector Stealer"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 13:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
      hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
      tags = "APT, DEMO, EXE, FILE, G0007, GEN, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "NvCpld.dll" fullword ascii
      $s1 = "NvStop" fullword ascii
      $s2 = "NvStart" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}