rule ps1_toolkit_Inveigh_BruteForce_RID3303 : DEMO FILE HKTL SCRIPT T1059_001 T1110 {
   meta:
      description = "Semiautomatically generated YARA rule - file Inveigh-BruteForce.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 14:29:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
      $s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
      $s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}