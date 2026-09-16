rule EquationGroup_ebbisland_RID3067 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ebbisland"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eba07c98c7e960bb6c71dafde85f5da9f74fd61bc87793c87e04b1ae2d77e977"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s [-V] -t <target_ip> -p port" fullword ascii
      $x2 = "error - shellcode not as expected - unable to fix up" fullword ascii
      $x3 = "WARNING - core wipe mode - this will leave a core file on target" fullword ascii
      $x4 = "[-C] wipe target core file (leaves less incriminating core on failed target)" fullword ascii
      $x5 = "-A <jumpAddr> (shellcode address)" fullword ascii
      $x6 = "*** Insane undocumented incremental port mode!!! ***" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}