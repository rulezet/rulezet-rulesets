rule Winnti_fonfig_RID2C62 : CHINA DEMO EXE FILE G0044 MAL {
   meta:
      description = "Winnti sample - file fonfig.exe"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2017/01/25/detecting-threat-actors-in-recent-german-industrial-attacks-with-windows-defender-atp?source=mmpc"
      date = "2017-01-25 09:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"
      tags = "CHINA, DEMO, EXE, FILE, G0044, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mciqtz.exe" fullword wide
      $s2 = "knat9y7m" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}