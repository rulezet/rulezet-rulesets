rule sig_238_TELNET {
   meta:
      description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
      id = "fae22e0f-2f69-5dc6-984c-2c07530ad11a"
   strings:
      $s0 = "TELNET [host [port]]" fullword wide
      $s2 = "TELNET.EXE" fullword wide
      $s4 = "Microsoft(R) Windows(R) Millennium Operating System" fullword wide
      $s14 = "Software\\Microsoft\\Telnet" fullword wide
   condition:
      all of them
}