rule TTP_XOR_QUAD_CurrentVersionRun_9298 {
  strings:
    $key_9298 = { c1 f7 [2] e5 f9 [2] ce d5 [2] e0 f7 [2] f4 ec [2] fb f6 [2] e5 eb [2] e7 ea [2] fc ec [2] e0 eb [2] fc c4 }

  condition:
    any of them
}