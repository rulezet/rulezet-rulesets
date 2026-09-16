rule EquationGroup_sshobo {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"
      id = "b9392aec-34a8-5ad2-b3fd-eea907d19701"
   strings:
      $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
      $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
      $x3 = "~#  - list forwarded connections" fullword ascii
      $x4 = "packet_inject_ignore: block" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and all of them )
}