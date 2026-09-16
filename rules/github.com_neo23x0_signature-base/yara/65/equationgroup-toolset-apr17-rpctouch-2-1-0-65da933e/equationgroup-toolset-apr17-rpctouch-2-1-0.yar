rule EquationGroup_Toolset_Apr17_Rpctouch_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"
      id = "0691768b-ca98-5722-8468-737c4966d54d"
   strings:
      $x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
      $x2 = "[*] SMB String: %s (%s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}