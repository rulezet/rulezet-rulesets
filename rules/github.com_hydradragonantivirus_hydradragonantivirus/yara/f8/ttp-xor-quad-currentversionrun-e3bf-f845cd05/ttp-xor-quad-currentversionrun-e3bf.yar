rule TTP_XOR_QUAD_CurrentVersionRun_e3bf {
  strings:
    $key_e3bf = { b0 d0 [2] 94 de [2] bf f2 [2] 91 d0 [2] 85 cb [2] 8a d1 [2] 94 cc [2] 96 cd [2] 8d cb [2] 91 cc [2] 8d e3 }

  condition:
    any of them
}