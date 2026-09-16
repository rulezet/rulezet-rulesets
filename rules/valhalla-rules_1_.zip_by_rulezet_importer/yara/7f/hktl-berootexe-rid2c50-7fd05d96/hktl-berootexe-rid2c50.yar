rule HKTL_beRootexe_RID2C50 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects beRoot.exe which checks common Windows missconfigurations"
      author = "Florian Roth"
      reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
      date = "2018-07-25 09:43:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "865b3b8ec9d03d3475286c3030958d90fc72b21b0dca38e5bf8e236602136dd7"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "checks.webclient.secretsdump(" ascii
      $s2 = "beroot.modules" fullword ascii
      $s3 = "beRoot.exe.manifest" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 18000KB and 1 of them )
}