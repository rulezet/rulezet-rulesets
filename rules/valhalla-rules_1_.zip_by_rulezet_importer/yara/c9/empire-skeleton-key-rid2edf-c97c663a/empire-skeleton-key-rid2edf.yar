rule Empire_skeleton_key_RID2EDF : DEMO SCRIPT SUSP T1059_001 T1098_004 T1547_008 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 11:33:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001, T1098_004, T1547_008"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "script += \"Invoke-Mimikatz -Command '\\\"\" + command + \"\\\"';\"" fullword ascii
      $s2 = "script += '\"Skeleton key implanted. Use password \\'mimikatz\\' for access.\"'" fullword ascii
      $s3 = "command = \"misc::skeleton\"" fullword ascii
      $s4 = "\"ONLY APPLICABLE ON DOMAIN CONTROLLERS!\")," fullword ascii
   condition: 
      filesize < 6KB and 2 of them
}