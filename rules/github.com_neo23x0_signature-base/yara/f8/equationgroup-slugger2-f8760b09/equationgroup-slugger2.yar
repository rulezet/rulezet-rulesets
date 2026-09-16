rule EquationGroup_slugger2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"
      id = "3787a39e-0123-5b46-90c9-6b772b1fd96c"
   strings:
      $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
      $x2 = "command must be less than 61 chars" fullword ascii

      $s1 = "__rw_read_waiting" ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "__mutexkind" ascii
      $s4 = "__rw_pshared" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ($x*) ) ) or ( all of them )
}