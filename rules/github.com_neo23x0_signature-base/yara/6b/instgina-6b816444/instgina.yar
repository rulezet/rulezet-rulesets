rule InstGina {
   meta:
      description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "5317fbc39508708534246ef4241e78da41a4f31c"
      id = "ccbda689-e61a-501d-a8ed-62e3c1c20289"
   strings:
      $s0 = "To Open Registry" fullword ascii
      $s4 = "I love Candy very much!!" ascii
      $s5 = "GinaDLL" fullword ascii
   condition:
      all of them
}