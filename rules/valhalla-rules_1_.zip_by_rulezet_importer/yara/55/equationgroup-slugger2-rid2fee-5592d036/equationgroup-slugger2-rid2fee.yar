rule EquationGroup_slugger2_RID2FEE : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
      $x2 = "command must be less than 61 chars" fullword ascii
      $s1 = "__rw_read_waiting" ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "__mutexkind" ascii
      $s4 = "__rw_pshared" ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ( $x* ) ) ) or ( all of them )
}