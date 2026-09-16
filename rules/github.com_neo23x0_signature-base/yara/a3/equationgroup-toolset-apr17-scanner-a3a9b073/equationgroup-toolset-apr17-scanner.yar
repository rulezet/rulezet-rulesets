rule EquationGroup_Toolset_Apr17_scanner {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f180bdb247687ea9f1b58aded225d5c80a13327422cd1e0515ea891166372c53"
      id = "603c82d0-2e65-5353-a109-5f69697cffa4"
   strings:
      $x1 = "+daemon_version,system,processor,refid,clock" fullword ascii
      $x2 = "Usage: %s typeofscan IP_address" fullword ascii
      $x3 = "# scanning ip  %d.%d.%d.%d" fullword ascii
      $x4 = "Welcome to the network scanning tool" fullword ascii
      $x5 = "***** %s ***** (length %d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them )
}