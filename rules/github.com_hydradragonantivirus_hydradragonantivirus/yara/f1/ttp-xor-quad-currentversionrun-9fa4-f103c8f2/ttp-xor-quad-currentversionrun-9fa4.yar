rule TTP_XOR_QUAD_CurrentVersionRun_9fa4 {
  strings:
    $key_9fa4 = { cc cb [2] e8 c5 [2] c3 e9 [2] ed cb [2] f9 d0 [2] f6 ca [2] e8 d7 [2] ea d6 [2] f1 d0 [2] ed d7 [2] f1 f8 }

  condition:
    any of them
}