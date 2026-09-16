rule EquationGroup_ewok_RID2E79 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:16:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Example: ewok -t target public" fullword ascii
      $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
      $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
      $x4 = "--- ewok version" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 80KB and 1 of them )
}