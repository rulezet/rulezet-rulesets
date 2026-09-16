rule TTP_XOR_QUAD_CurrentVersionRun_9296 {
  strings:
    $key_9296 = { c1 f9 [2] e5 f7 [2] ce db [2] e0 f9 [2] f4 e2 [2] fb f8 [2] e5 e5 [2] e7 e4 [2] fc e2 [2] e0 e5 [2] fc ca }

  condition:
    any of them
}