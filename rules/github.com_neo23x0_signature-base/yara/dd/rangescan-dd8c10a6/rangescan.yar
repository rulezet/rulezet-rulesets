rule RangeScan {
   meta:
      description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
      id = "143d9e1e-41e2-579a-beee-30da2cf068f7"
   strings:
      $s0 = "RangeScan.EXE" fullword wide
      $s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
      $s9 = "Produced by isn0" fullword ascii
      $s10 = "RangeScan" fullword wide
      $s20 = "%d-%d-%d %d:%d:%d" fullword ascii
   condition:
      3 of them
}