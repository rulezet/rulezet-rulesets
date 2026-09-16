rule Empire_Invoke_Gen_RID2DB7 : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files Invoke-DCSync.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 10:43:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Shellcode1 += 0x48" fullword ascii
      $s2 = "$PEHandle = [IntPtr]::Zero" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 3000KB and 1 of them ) or all of them
}