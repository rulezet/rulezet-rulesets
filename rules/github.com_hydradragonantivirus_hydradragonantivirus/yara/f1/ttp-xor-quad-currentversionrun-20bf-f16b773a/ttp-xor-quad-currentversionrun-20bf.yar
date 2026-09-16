rule TTP_XOR_QUAD_CurrentVersionRun_20bf {
  strings:
    $key_20bf = { 73 d0 [2] 57 de [2] 7c f2 [2] 52 d0 [2] 46 cb [2] 49 d1 [2] 57 cc [2] 55 cd [2] 4e cb [2] 52 cc [2] 4e e3 }

  condition:
    any of them
}