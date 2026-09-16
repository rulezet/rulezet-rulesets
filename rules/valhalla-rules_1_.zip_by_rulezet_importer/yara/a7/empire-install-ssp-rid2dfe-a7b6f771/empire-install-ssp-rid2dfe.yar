rule Empire_Install_SSP_RID2DFE : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Install-SSP.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7fd921a23950334257dda57b99e03c1e1594d736aab2dbfe9583f99cd9b1d165"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Install-SSP -Path .\\mimilib.dll" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}