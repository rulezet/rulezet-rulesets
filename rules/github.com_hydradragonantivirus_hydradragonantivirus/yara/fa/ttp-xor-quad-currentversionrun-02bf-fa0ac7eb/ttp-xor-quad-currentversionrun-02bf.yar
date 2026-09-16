rule TTP_XOR_QUAD_CurrentVersionRun_02bf {
  strings:
    $key_02bf = { 51 d0 [2] 75 de [2] 5e f2 [2] 70 d0 [2] 64 cb [2] 6b d1 [2] 75 cc [2] 77 cd [2] 6c cb [2] 70 cc [2] 6c e3 }

  condition:
    any of them
}