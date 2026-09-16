rule TTP_XOR_QUAD_CurrentVersionRun_b8c9 {
  strings:
    $key_b8c9 = { eb a6 [2] cf a8 [2] e4 84 [2] ca a6 [2] de bd [2] d1 a7 [2] cf ba [2] cd bb [2] d6 bd [2] ca ba [2] d6 95 }

  condition:
    any of them
}