rule TTP_XOR_QUAD_CurrentVersionRun_9086 {
  strings:
    $key_9086 = { c3 e9 [2] e7 e7 [2] cc cb [2] e2 e9 [2] f6 f2 [2] f9 e8 [2] e7 f5 [2] e5 f4 [2] fe f2 [2] e2 f5 [2] fe da }

  condition:
    any of them
}