rule VUBrute_VUBrute {
   meta:
      description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "22.11.14"
      score = 70
      hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
      id = "7ac74c85-465c-5eb5-8e91-004f28cabb75"
   strings:
      $s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
      $s1 = "http://ubrute.com" fullword ascii
      $s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
      $s14 = "error.txt" fullword ascii
   condition:
      all of them
}