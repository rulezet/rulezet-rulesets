rule PowerShell_Emp_Eval_Jul17_A1_RID3141 : DEMO EXE FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects suspicious sample with PowerShell content "
      author = "Florian Roth"
      reference = "PowerShell Empire Eval"
      date = "2017-07-27 13:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"
      tags = "DEMO, EXE, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "powershell" wide
      $s2 = "pshcmd" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them )
}