rule sig_238_letmein {
   meta:
      description = "Disclosed hacktool set (old stuff) - file letmein.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
      id = "5dba055f-1928-534a-8d0e-11dda56d93b7"
   strings:
      $s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
      $s6 = "Error get users from server!" fullword ascii
      $s7 = "get in nt by name and null" fullword ascii
      $s16 = "get something from nt, hold by killusa." fullword ascii
   condition:
      all of them
}