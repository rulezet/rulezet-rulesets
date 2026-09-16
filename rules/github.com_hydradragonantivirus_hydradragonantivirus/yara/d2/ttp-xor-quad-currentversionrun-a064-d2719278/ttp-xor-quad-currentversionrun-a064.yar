rule TTP_XOR_QUAD_CurrentVersionRun_a064 {
  strings:
    $key_a064 = { f3 0b [2] d7 05 [2] fc 29 [2] d2 0b [2] c6 10 [2] c9 0a [2] d7 17 [2] d5 16 [2] ce 10 [2] d2 17 [2] ce 38 }

  condition:
    any of them
}