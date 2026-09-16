rule LM_hash_empty_String_RID2F11 : DEMO HKTL {
   meta:
      description = "Detects the empty LM hash on disk/in memory/as output from hacking tools"
      author = "Florian Roth"
      reference = "-"
      date = "2016-06-03 11:41:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
      $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
   condition: 
      1 of them
}