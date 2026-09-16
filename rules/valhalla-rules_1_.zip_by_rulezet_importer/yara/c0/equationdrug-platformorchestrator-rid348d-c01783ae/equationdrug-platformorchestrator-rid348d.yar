rule EquationDrug_PlatformOrchestrator_RID348D : APT DEMO {
   meta:
      description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 15:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SERVICES.EXE" fullword wide
      $s1 = "\\command.com" wide
      $s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s3 = "LSASS.EXE" fullword wide
      $s4 = "Windows Configuration Services" fullword wide
      $s8 = "unilay.dll" fullword ascii
   condition: 
      all of them
}