rule TTP_XOR_QUAD_CurrentVersionRun_a058 {
  strings:
    $key_a058 = { f3 37 [2] d7 39 [2] fc 15 [2] d2 37 [2] c6 2c [2] c9 36 [2] d7 2b [2] d5 2a [2] ce 2c [2] d2 2b [2] ce 04 }

  condition:
    any of them
}