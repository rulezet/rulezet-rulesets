rule Empire_Invoke_PostExfil_RID303B : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-PostExfil.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "# upload to a specified exfil URI" fullword ascii
      $s2 = "Server path to exfil to." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}