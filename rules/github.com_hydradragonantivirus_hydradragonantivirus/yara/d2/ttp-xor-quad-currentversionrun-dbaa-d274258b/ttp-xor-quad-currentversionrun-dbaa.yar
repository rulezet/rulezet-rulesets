rule TTP_XOR_QUAD_CurrentVersionRun_dbaa {
  strings:
    $key_dbaa = { 88 c5 [2] ac cb [2] 87 e7 [2] a9 c5 [2] bd de [2] b2 c4 [2] ac d9 [2] ae d8 [2] b5 de [2] a9 d9 [2] b5 f6 }

  condition:
    any of them
}