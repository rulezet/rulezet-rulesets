rule EditKeyLogReadMe {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
      id = "db083c04-9e5c-5cfd-b4d4-eecf28191b6b"
   strings:
      $s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
      $s1 = "WinEggDrop.DLL" fullword ascii
      $s2 = "nc.exe" fullword ascii
      $s3 = "KeyLog.exe" fullword ascii
      $s4 = "EditKeyLog.exe" fullword ascii
      $s5 = "wineggdrop" fullword ascii
   condition:
      3 of them
}