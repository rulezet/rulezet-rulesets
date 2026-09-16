rule TTP_XOR_QUAD_CurrentVersionRun_9198 {
  strings:
    $key_9198 = { c2 f7 [2] e6 f9 [2] cd d5 [2] e3 f7 [2] f7 ec [2] f8 f6 [2] e6 eb [2] e4 ea [2] ff ec [2] e3 eb [2] ff c4 }

  condition:
    any of them
}