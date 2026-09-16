rule TTP_XOR_QUAD_CurrentVersionRun_25bf {
  strings:
    $key_25bf = { 76 d0 [2] 52 de [2] 79 f2 [2] 57 d0 [2] 43 cb [2] 4c d1 [2] 52 cc [2] 50 cd [2] 4b cb [2] 57 cc [2] 4b e3 }

  condition:
    any of them
}