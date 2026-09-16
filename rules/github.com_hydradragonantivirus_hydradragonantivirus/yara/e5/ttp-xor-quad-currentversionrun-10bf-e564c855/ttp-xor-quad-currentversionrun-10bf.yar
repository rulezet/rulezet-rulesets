rule TTP_XOR_QUAD_CurrentVersionRun_10bf {
  strings:
    $key_10bf = { 43 d0 [2] 67 de [2] 4c f2 [2] 62 d0 [2] 76 cb [2] 79 d1 [2] 67 cc [2] 65 cd [2] 7e cb [2] 62 cc [2] 7e e3 }

  condition:
    any of them
}