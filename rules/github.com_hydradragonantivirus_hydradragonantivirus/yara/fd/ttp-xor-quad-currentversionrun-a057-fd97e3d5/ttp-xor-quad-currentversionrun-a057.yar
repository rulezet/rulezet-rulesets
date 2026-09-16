rule TTP_XOR_QUAD_CurrentVersionRun_a057 {
  strings:
    $key_a057 = { f3 38 [2] d7 36 [2] fc 1a [2] d2 38 [2] c6 23 [2] c9 39 [2] d7 24 [2] d5 25 [2] ce 23 [2] d2 24 [2] ce 0b }

  condition:
    any of them
}