rule TTP_XOR_QUAD_CurrentVersionRun_89af {
  strings:
    $key_89af = { da c0 [2] fe ce [2] d5 e2 [2] fb c0 [2] ef db [2] e0 c1 [2] fe dc [2] fc dd [2] e7 db [2] fb dc [2] e7 f3 }

  condition:
    any of them
}