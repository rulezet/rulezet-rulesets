rule EquationGroup_Toolset_Apr17_regprobe_RID354C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "99a42440d4cf1186aad1fd09072bd1265e7c6ebbc8bcafc28340b4fe371767de"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
      $x2 = "key does not exist or pinging w2k system" fullword ascii
      $x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}