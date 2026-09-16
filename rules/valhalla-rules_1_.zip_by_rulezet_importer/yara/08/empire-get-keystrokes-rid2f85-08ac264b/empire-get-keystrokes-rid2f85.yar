rule Empire_Get_Keystrokes_RID2F85 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Get-Keystrokes.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}