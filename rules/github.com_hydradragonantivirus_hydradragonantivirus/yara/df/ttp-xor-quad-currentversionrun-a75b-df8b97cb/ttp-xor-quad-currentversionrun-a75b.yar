rule TTP_XOR_QUAD_CurrentVersionRun_a75b {
  strings:
    $key_a75b = { f4 34 [2] d0 3a [2] fb 16 [2] d5 34 [2] c1 2f [2] ce 35 [2] d0 28 [2] d2 29 [2] c9 2f [2] d5 28 [2] c9 07 }

  condition:
    any of them
}