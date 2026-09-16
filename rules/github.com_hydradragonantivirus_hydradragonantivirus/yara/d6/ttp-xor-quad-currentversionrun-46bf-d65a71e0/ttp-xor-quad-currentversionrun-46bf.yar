rule TTP_XOR_QUAD_CurrentVersionRun_46bf {
  strings:
    $key_46bf = { 15 d0 [2] 31 de [2] 1a f2 [2] 34 d0 [2] 20 cb [2] 2f d1 [2] 31 cc [2] 33 cd [2] 28 cb [2] 34 cc [2] 28 e3 }

  condition:
    any of them
}