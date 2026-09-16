rule PP_CN_APT_ZeroT_7_RID2CCE : APT CHINA DEMO EXE FILE {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03 10:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fc2d47d91ad8517a4a974c4570b346b41646fac333d219d2f1282c96b4571478"
      tags = "APT, CHINA, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "RasTls.dll" fullword ascii
      $s2 = "RasTls.exe" fullword ascii
      $s4 = "LOADER ERROR" fullword ascii
      $s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}