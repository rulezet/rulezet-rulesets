rule Winnti_NlaifSvc_RID2CFF : CHINA DEMO EXE FILE G0044 MAL {
   meta:
      description = "Winnti sample - file NlaifSvc.dll"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2017/01/25/detecting-threat-actors-in-recent-german-industrial-attacks-with-windows-defender-atp?source=mmpc"
      date = "2017-01-25 10:13:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"
      tags = "CHINA, DEMO, EXE, FILE, G0044, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cracked by ximo" ascii
      $s1 = "Yqrfpk" fullword ascii
      $s2 = "IVVTOC" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 900KB and ( 1 of ( $x* ) or 2 of them ) ) or ( 3 of them )
}