rule Powershell_Attack_Scripts {
   meta:
      description = "Powershell Attack Scripts"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2016-03-09"
      score = 70
      id = "e8c4a672-229b-56c8-811b-071ae9ff341e"
   strings:
      $s1 = "PowershellMafia\\Invoke-Shellcode.ps1" ascii
      $s2 = "Nishang\\Do-Exfiltration.ps1" ascii
      $s3 = "PowershellMafia\\Invoke-Mimikatz.ps1" ascii
      $s4 = "Inveigh\\Inveigh.ps1" ascii
   condition:
      1 of them
}