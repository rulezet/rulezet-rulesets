rule TTP_XOR_QUAD_CurrentVersionRun_9286 {
  strings:
    $key_9286 = { c1 e9 [2] e5 e7 [2] ce cb [2] e0 e9 [2] f4 f2 [2] fb e8 [2] e5 f5 [2] e7 f4 [2] fc f2 [2] e0 f5 [2] fc da }

  condition:
    any of them
}