rule TempRacer_RID2A94 : DEMO EXE FILE HKTL T1068 T1087_001 {
   meta:
      description = "Detects privilege escalation tool - file TempRacer_RID2A94.exe"
      author = "Florian Roth"
      reference = "http://www.darknet.org.uk/2016/03/tempracer-windows-privilege-escalation-tool/"
      date = "2016-03-30 06:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, HKTL, T1068, T1087_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\obj\\Release\\TempRacer_RID2A94.pdb" ascii
      $s2 = "[+] Injecting into " fullword wide
      $s3 = "net localgroup administrators alex /add" fullword wide
      $s4 = "[+] File: {0} renamed to {1}" fullword wide
      $s5 = "[+] Blocking " fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 25KB and 1 of them ) or ( 4 of them )
}