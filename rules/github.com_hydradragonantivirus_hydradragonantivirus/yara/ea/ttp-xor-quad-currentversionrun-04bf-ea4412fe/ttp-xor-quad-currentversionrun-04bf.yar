rule TTP_XOR_QUAD_CurrentVersionRun_04bf {
  strings:
    $key_04bf = { 57 d0 [2] 73 de [2] 58 f2 [2] 76 d0 [2] 62 cb [2] 6d d1 [2] 73 cc [2] 71 cd [2] 6a cb [2] 76 cc [2] 6a e3 }

  condition:
    any of them
}