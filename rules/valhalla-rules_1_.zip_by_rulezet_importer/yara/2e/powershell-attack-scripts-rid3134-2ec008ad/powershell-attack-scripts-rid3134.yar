rule Powershell_Attack_Scripts_RID3134 : DEMO HKTL SCRIPT T1059_001 {
   meta:
      description = "Powershell Attack Scripts"
      author = "Florian Roth"
      reference = "-"
      date = "2016-03-09 13:12:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "PowershellMafia\\Invoke-Shellcode.ps1" ascii
      $s2 = "Nishang\\Do-Exfiltration.ps1" ascii
      $s3 = "PowershellMafia\\Invoke-Mimikatz.ps1" ascii
      $s4 = "Inveigh\\Inveigh.ps1" ascii
   condition: 
      1 of them
}