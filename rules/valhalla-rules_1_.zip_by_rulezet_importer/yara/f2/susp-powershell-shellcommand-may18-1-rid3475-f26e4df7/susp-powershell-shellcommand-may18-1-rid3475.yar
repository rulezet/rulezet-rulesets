rule SUSP_Powershell_ShellCommand_May18_1_RID3475 : DEMO HKTL SCRIPT SUSP T1059_001 {
   meta:
      description = "Detects a supcicious powershell commandline"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 15:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
      tags = "DEMO, HKTL, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "powershell -nop -ep bypass -Command" ascii
   condition: 
      filesize < 3KB and 1 of them
}