rule TTP_XOR_QUAD_CurrentVersionRun_40bf {
  strings:
    $key_40bf = { 13 d0 [2] 37 de [2] 1c f2 [2] 32 d0 [2] 26 cb [2] 29 d1 [2] 37 cc [2] 35 cd [2] 2e cb [2] 32 cc [2] 2e e3 }

  condition:
    any of them
}