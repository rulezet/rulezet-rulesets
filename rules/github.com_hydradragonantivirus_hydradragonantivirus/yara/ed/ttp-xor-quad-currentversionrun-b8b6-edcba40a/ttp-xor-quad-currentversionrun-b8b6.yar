rule TTP_XOR_QUAD_CurrentVersionRun_b8b6 {
  strings:
    $key_b8b6 = { eb d9 [2] cf d7 [2] e4 fb [2] ca d9 [2] de c2 [2] d1 d8 [2] cf c5 [2] cd c4 [2] d6 c2 [2] ca c5 [2] d6 ea }

  condition:
    any of them
}