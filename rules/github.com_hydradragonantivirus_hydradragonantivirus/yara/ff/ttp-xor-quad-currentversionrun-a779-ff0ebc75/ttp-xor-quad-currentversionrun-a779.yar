rule TTP_XOR_QUAD_CurrentVersionRun_a779 {
  strings:
    $key_a779 = { f4 16 [2] d0 18 [2] fb 34 [2] d5 16 [2] c1 0d [2] ce 17 [2] d0 0a [2] d2 0b [2] c9 0d [2] d5 0a [2] c9 25 }

  condition:
    any of them
}