rule sig_238_listip {
   meta:
      description = "Disclosed hacktool set (old stuff) - file listip.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
      id = "417faf20-ee07-5c3e-bfcf-89599e38e62e"
   strings:
      $s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
      $s2 = "ERROR No.2!!! Program Terminate." fullword ascii
      $s4 = "Local Host Name: %s" fullword ascii
      $s5 = "Packed by exe32pack 1.38" fullword ascii
      $s7 = "Local Computer Name: %s" fullword ascii
      $s8 = "Local IP Adress: %s" fullword ascii
   condition:
      all of them
}