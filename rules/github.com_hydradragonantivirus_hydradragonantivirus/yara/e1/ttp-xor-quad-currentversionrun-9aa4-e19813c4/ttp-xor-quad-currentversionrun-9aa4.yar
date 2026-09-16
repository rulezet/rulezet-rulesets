rule TTP_XOR_QUAD_CurrentVersionRun_9aa4 {
  strings:
    $key_9aa4 = { c9 cb [2] ed c5 [2] c6 e9 [2] e8 cb [2] fc d0 [2] f3 ca [2] ed d7 [2] ef d6 [2] f4 d0 [2] e8 d7 [2] f4 f8 }

  condition:
    any of them
}