rule EquationGroup_Toolset_Apr17_regprobe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "99a42440d4cf1186aad1fd09072bd1265e7c6ebbc8bcafc28340b4fe371767de"
      id = "184618b7-a24c-5a8c-9fb2-a5a07f1a0299"
   strings:
      $x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
      $x2 = "key does not exist or pinging w2k system" fullword ascii
      $x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}