rule TTP_XOR_QUAD_CurrentVersionRun_a004 {
  strings:
    $key_a004 = { f3 6b [2] d7 65 [2] fc 49 [2] d2 6b [2] c6 70 [2] c9 6a [2] d7 77 [2] d5 76 [2] ce 70 [2] d2 77 [2] ce 58 }

  condition:
    any of them
}