rule EquationGroup_sshobo_RID2F51 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:52:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
      $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
      $x3 = "~#  - list forwarded connections" fullword ascii
      $x4 = "packet_inject_ignore: block" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 600KB and all of them )
}