rule EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1_RID38F4 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:43:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Error appending shellcode buffer" fullword ascii
      $x2 = "[-] Shellcode is too big" fullword ascii
      $x3 = "[+] Exploit Payload Sent!" fullword ascii
      $x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 1 of them )
}