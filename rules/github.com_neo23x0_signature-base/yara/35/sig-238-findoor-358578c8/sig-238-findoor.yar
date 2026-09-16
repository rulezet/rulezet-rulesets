rule sig_238_findoor {
   meta:
      description = "Disclosed hacktool set (old stuff) - file findoor.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
      id = "61215a76-8c29-505d-bfef-a5f13fec476c"
   strings:
      $s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
      $s8 = "PASS hacker@hacker.com" fullword ascii
      $s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
      $s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
      $s11 = "http://isno.yeah.net" fullword ascii
   condition:
      4 of them
}