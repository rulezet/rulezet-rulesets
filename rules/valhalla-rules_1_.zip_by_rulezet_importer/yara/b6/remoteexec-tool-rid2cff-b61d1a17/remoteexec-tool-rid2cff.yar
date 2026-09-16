rule RemoteExec_Tool_RID2CFF : APT DEMO EXE FILE {
   meta:
      description = "Remote Access Tool used in APT Terracotta"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
      date = "2015-08-04 10:13:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cmd.exe /q /c \"%s\"" fullword ascii
      $s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii
      $s2 = "This is a service executable! Couldn't start directly." fullword ascii
      $s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii
      $s4 = "TermHlp_stdout" fullword ascii
      $s5 = "TermHlp_stdin" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 75KB and 4 of ( $s* )
}