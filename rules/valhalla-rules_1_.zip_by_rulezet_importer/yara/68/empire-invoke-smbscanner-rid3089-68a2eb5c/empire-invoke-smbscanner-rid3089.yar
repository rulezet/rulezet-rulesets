rule Empire_Invoke_SmbScanner_RID3089 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:44:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}