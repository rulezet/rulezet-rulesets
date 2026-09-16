rule TTP_XOR_QUAD_CurrentVersionRun_9590 {
  strings:
    $key_9590 = { c6 ff [2] e2 f1 [2] c9 dd [2] e7 ff [2] f3 e4 [2] fc fe [2] e2 e3 [2] e0 e2 [2] fb e4 [2] e7 e3 [2] fb cc }

  condition:
    any of them
}