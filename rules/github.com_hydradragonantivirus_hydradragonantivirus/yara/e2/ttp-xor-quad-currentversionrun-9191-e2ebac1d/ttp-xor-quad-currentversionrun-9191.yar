rule TTP_XOR_QUAD_CurrentVersionRun_9191 {
  strings:
    $key_9191 = { c2 fe [2] e6 f0 [2] cd dc [2] e3 fe [2] f7 e5 [2] f8 ff [2] e6 e2 [2] e4 e3 [2] ff e5 [2] e3 e2 [2] ff cd }

  condition:
    any of them
}