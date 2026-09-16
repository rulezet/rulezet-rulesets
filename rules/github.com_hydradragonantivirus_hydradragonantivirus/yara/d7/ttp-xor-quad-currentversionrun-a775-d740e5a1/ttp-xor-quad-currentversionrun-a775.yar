rule TTP_XOR_QUAD_CurrentVersionRun_a775 {
  strings:
    $key_a775 = { f4 1a [2] d0 14 [2] fb 38 [2] d5 1a [2] c1 01 [2] ce 1b [2] d0 06 [2] d2 07 [2] c9 01 [2] d5 06 [2] c9 29 }

  condition:
    any of them
}