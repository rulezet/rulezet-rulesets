rule EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
      id = "1a3fe877-b9ae-50e4-bb1a-c9dcd4d4a657"
   strings:
      $x1 = "[-] Error appending shellcode buffer" fullword ascii
      $x2 = "[-] Shellcode is too big" fullword ascii
      $x3 = "[+] Exploit Payload Sent!" fullword ascii
      $x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}