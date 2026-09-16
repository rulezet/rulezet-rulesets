rule TTP_XOR_QUAD_CurrentVersionRun_77bf {
  strings:
    $key_77bf = { 24 d0 [2] 00 de [2] 2b f2 [2] 05 d0 [2] 11 cb [2] 1e d1 [2] 00 cc [2] 02 cd [2] 19 cb [2] 05 cc [2] 19 e3 }

  condition:
    any of them
}