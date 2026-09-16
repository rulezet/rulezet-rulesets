rule EquationGroup_Toolset_Apr17_Eclipsedwing_Rpcproxy_Pcdlllauncher_RID403A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 23:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "48251fb89c510fb3efa14c4b5b546fbde918ed8bb25f041a801e3874bd4f60f8"
      hash2 = "237c22f4d43fdacfcbd6e1b5f1c71578279b7b06ea8e512b4b6b50f10e8ccf10"
      hash3 = "79a584c127ac6a5e96f02a9c5288043ceb7445de2840b608fc99b55cf86507ed"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Failed to Prepare Payload!" fullword ascii
      $x2 = "ShellcodeStartOffset" fullword ascii
      $x3 = "[*] Waiting for AuthCode from exploit" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}