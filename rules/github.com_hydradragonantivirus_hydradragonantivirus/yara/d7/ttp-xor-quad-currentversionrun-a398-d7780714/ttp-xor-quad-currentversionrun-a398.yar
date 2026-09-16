rule TTP_XOR_QUAD_CurrentVersionRun_a398 {
  strings:
    $key_a398 = { f0 f7 [2] d4 f9 [2] ff d5 [2] d1 f7 [2] c5 ec [2] ca f6 [2] d4 eb [2] d6 ea [2] cd ec [2] d1 eb [2] cd c4 }

  condition:
    any of them
}