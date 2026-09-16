rule TTP_XOR_QUAD_CurrentVersionRun_95e0 {
  strings:
    $key_95e0 = { c6 8f [2] e2 81 [2] c9 ad [2] e7 8f [2] f3 94 [2] fc 8e [2] e2 93 [2] e0 92 [2] fb 94 [2] e7 93 [2] fb bc }

  condition:
    any of them
}