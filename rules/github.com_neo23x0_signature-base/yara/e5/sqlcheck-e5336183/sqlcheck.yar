rule sqlcheck {
   meta:
      description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
      id = "a72d38ef-b2e7-5051-8538-724d9e95fa6a"
   strings:
      $s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
      $s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
      $s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
      $s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
      $s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii
   condition:
      3 of them
}