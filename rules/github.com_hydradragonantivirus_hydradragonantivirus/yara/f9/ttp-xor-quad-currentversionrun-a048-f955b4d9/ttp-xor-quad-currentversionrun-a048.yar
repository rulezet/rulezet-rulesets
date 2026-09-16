rule TTP_XOR_QUAD_CurrentVersionRun_a048 {
  strings:
    $key_a048 = { f3 27 [2] d7 29 [2] fc 05 [2] d2 27 [2] c6 3c [2] c9 26 [2] d7 3b [2] d5 3a [2] ce 3c [2] d2 3b [2] ce 14 }

  condition:
    any of them
}