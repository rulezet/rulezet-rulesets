rule TTP_XOR_QUAD_CurrentVersionRun_e7bf {
  strings:
    $key_e7bf = { b4 d0 [2] 90 de [2] bb f2 [2] 95 d0 [2] 81 cb [2] 8e d1 [2] 90 cc [2] 92 cd [2] 89 cb [2] 95 cc [2] 89 e3 }

  condition:
    any of them
}