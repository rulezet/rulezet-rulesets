rule TTP_XOR_QUAD_CurrentVersionRun_9196 {
  strings:
    $key_9196 = { c2 f9 [2] e6 f7 [2] cd db [2] e3 f9 [2] f7 e2 [2] f8 f8 [2] e6 e5 [2] e4 e4 [2] ff e2 [2] e3 e5 [2] ff ca }

  condition:
    any of them
}