rule NTLM_Dump_Output {
   meta:
      description = "NTML Hash Dump output file - John/LC format"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2015-10-01"
      score = 75
      id = "d17ee473-317b-57d4-8ea8-7c89e8f2b2ed"
   strings:
      $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
      $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
   condition:
      1 of them
}