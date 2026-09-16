rule EquationGroup_Toolset_Apr17_Englishmansdentist_1_2_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"
      id = "76367c53-9b48-59a1-9ac9-8649fd833fe3"
   strings:
      $x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
      $x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}