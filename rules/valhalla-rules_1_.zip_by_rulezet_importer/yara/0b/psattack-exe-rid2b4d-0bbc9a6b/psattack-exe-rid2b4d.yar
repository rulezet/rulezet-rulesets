rule PSAttack_EXE_RID2B4D : DEMO EXE HKTL SCRIPT T1059_001 {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.exe"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09 09:00:41"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\PSAttack.pdb" 
      $s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
      $s2 = "PSAttack.Modules." ascii
      $s3 = "PSAttack.PSAttackProcessing" fullword ascii
      $s4 = "PSAttack.Modules.key.txt" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and ( $x1 or 2 of ( $s* ) ) ) or 3 of them
}