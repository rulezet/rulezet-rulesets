rule TTP_XOR_QUAD_CurrentVersionRun_53bf {
  strings:
    $key_53bf = { 00 d0 [2] 24 de [2] 0f f2 [2] 21 d0 [2] 35 cb [2] 3a d1 [2] 24 cc [2] 26 cd [2] 3d cb [2] 21 cc [2] 3d e3 }

  condition:
    any of them
}