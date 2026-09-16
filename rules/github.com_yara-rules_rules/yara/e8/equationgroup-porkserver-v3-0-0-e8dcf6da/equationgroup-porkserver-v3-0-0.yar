rule EquationGroup_porkserver_v3_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "7b5f86e289047dd673e8a09438d49ec43832b561bac39b95098f5bf4095b8b4a"
   strings:
      $s1 = "%s: %s rpcprog=%d, rpcvers = %d/%d, proto=%s, wait.max=%d.%d, user.group=%s.%s builtin=%lx server=%s" fullword ascii
      $s2 = "%s/%s server failing (looping), service terminated" fullword ascii
      $s3 = "getpwnam: %s: No such user" fullword ascii
      $s4 = "execv %s: %m" fullword ascii
      $s5 = "%s/%s: getsockname: %m" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and 4 of them )
}