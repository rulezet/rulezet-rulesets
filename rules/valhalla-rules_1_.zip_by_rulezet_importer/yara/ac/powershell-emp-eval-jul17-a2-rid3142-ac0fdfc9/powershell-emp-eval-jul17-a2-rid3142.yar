rule PowerShell_Emp_Eval_Jul17_A2_RID3142 : DEMO EXE FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects suspicious sample with PowerShell content "
      author = "Florian Roth"
      reference = "PowerShell Empire Eval"
      date = "2017-07-27 13:14:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e14c139159c23fdc18969afe57ec062e4d3c28dd42a20bed8ddde37ab4351a51"
      tags = "DEMO, EXE, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\support\\Release\\ab.pdb" ascii
      $s2 = "powershell.exe" ascii fullword
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}