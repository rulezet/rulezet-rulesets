rule TTP_XOR_QUAD_CurrentVersionRun_01bf {
  strings:
    $key_01bf = { 52 d0 [2] 76 de [2] 5d f2 [2] 73 d0 [2] 67 cb [2] 68 d1 [2] 76 cc [2] 74 cd [2] 6f cb [2] 73 cc [2] 6f e3 }

  condition:
    any of them
}