rule KeeThief_PS_RID2B18 : DEMO FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file KeeThief.ps1"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29 08:51:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a3b976279ded8e64b548c1d487212b46b03aaec02cb6e199ea620bd04b8de42f"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "$WMIProcess = Get-WmiObject win32_process -Filter \"ProcessID = $($KeePassProcess.ID)\"" fullword ascii
      $x2 = "if($KeePassProcess.FileVersion -match '^2\\.') {" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7223 and filesize < 1000KB and ( 1 of ( $x* ) ) )
}