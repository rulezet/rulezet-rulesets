rule TTP_XOR_QUAD_CurrentVersionRun_a0a8 {
  strings:
    $key_a0a8 = { f3 c7 [2] d7 c9 [2] fc e5 [2] d2 c7 [2] c6 dc [2] c9 c6 [2] d7 db [2] d5 da [2] ce dc [2] d2 db [2] ce f4 }

  condition:
    any of them
}