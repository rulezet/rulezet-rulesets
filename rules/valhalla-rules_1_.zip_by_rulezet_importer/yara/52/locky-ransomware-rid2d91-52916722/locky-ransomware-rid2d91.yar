rule Locky_Ransomware_RID2D91 : CRIME DEMO MAL RANSOM {
   meta:
      description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8?environmentId=1"
      date = "2016-02-17 10:37:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "CRIME, DEMO, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } 
      $o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } 
   condition: 
      all of ( $o* )
}