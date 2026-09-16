rule TTP_XOR_QUAD_CurrentVersionRun_a764 {
  strings:
    $key_a764 = { f4 0b [2] d0 05 [2] fb 29 [2] d5 0b [2] c1 10 [2] ce 0a [2] d0 17 [2] d2 16 [2] c9 10 [2] d5 17 [2] c9 38 }

  condition:
    any of them
}