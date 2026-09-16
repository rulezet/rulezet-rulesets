rule Sofacy_CollectorStealer_Gen3_RID31F8 : APT DEMO EXE FILE G0007 GEN RUSSIA {
   meta:
      description = "File collectors / USB stealers - Generic"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 13:45:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0007, GEN, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NvCpld.dll" fullword ascii
      $s4 = "NvStart" fullword ascii
      $s5 = "NvStop" fullword ascii
      $a1 = "%.4d%.2d%.2d%.2d%.2d%.2d%.2d%.4d" fullword wide
      $a2 = "IGFSRVC.dll" fullword wide
      $a3 = "Common User Interface" fullword wide
      $a4 = "igfsrvc Module" fullword wide
      $b1 = " Operating System                        " fullword wide
      $b2 = "Microsoft Corporation                                       " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and ( all of ( $s* ) and ( all of ( $a* ) or all of ( $b* ) ) )
}