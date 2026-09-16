rule snifferport {
   meta:
      description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "d14133b5eaced9b7039048d0767c544419473144"
      id = "5b903344-18d2-5d3d-be66-7260a5f3ea4b"
   strings:
      $s0 = "iphlpapi.DLL" fullword ascii
      $s5 = "ystem\\CurrentCorolSet\\" ascii
      $s11 = "Port.TX" fullword ascii
      $s12 = "32Next" fullword ascii
      $s13 = "V1.2 B" fullword ascii
   condition:
      all of them
}