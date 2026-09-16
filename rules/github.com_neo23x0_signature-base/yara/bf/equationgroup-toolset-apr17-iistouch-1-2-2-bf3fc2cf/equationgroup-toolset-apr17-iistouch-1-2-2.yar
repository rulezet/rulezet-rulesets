rule EquationGroup_Toolset_Apr17_Iistouch_1_2_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"
      id = "dd6ea8cc-505d-5c7c-a7ea-c5fa4f14b5ee"
   strings:
      $x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
      $x2 = "[+] IIS Target OS: %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and 1 of them )
}