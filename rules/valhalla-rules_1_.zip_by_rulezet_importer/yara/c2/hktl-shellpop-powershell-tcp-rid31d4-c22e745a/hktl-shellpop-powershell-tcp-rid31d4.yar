rule HKTL_shellpop_Powershell_TCP_RID31D4 : DEMO HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects malicious powershell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 13:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
      tags = "DEMO, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "Something went wrong with execution of command on the target" ascii
      $ = ";[byte[]]$bytes = 0..65535|%{0};$sendbytes =" ascii
   condition: 
      filesize < 3KB and 1 of them
}