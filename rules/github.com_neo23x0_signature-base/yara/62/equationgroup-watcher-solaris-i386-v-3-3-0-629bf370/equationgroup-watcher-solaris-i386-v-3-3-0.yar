rule EquationGroup_watcher_solaris_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "395ec2531970950ffafde234dded0cce0c95f1f9a22763d1d04caa060a5222bb"
      id = "e75c6ed9-b6e6-530d-a6ac-40bd0477754f"
   strings:
      $s1 = "getexecname" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s6 = "__fpstart" ascii
      $s12 = "GHFIJKLMNOPQRSTUVXW" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and all of them )
}