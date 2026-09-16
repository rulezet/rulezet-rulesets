rule CN_Honker_portRecall_bc_RID3003 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file bc.pl"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:21:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "print \"[*] Connected to remote host \\n\"; " fullword ascii
      $s1 = "print \"Usage: $0 [Host] [Port] \\n\\n\";  " fullword ascii
      $s5 = "print \"[*] Resolving HostName\\n\"; " fullword ascii
   condition: 
      filesize < 10KB and all of them
}