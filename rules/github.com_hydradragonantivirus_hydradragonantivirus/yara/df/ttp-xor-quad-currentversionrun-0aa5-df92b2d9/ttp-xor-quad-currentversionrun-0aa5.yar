rule TTP_XOR_QUAD_CurrentVersionRun_0aa5 {
  strings:
    $key_0aa5 = { 59 ca [2] 7d c4 [2] 56 e8 [2] 78 ca [2] 6c d1 [2] 63 cb [2] 7d d6 [2] 7f d7 [2] 64 d1 [2] 78 d6 [2] 64 f9 }

  condition:
    any of them
}