rule TTP_XOR_QUAD_CurrentVersionRun_dea5 {
  strings:
    $key_dea5 = { 8d ca [2] a9 c4 [2] 82 e8 [2] ac ca [2] b8 d1 [2] b7 cb [2] a9 d6 [2] ab d7 [2] b0 d1 [2] ac d6 [2] b0 f9 }

  condition:
    any of them
}