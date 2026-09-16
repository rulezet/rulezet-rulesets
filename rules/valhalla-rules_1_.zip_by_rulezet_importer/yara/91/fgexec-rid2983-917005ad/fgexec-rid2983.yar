rule fgexec_RID2983 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects a tool used by APT groups - file fgexec_RID2983.exe"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 23:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\fgexec_RID2983.pdb" ascii
      $x2 = "fgexec_RID2983 Remote Process Execution Tool" fullword ascii
      $x3 = "fgexec_RID2983 CallNamedPipe failed" fullword ascii
      $x4 = "fizzgig and the mighty foofus.net team" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of ( $x* ) ) or ( 3 of them )
}