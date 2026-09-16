rule TTP_XOR_QUAD_CurrentVersionRun_e1bf {
  strings:
    $key_e1bf = { b2 d0 [2] 96 de [2] bd f2 [2] 93 d0 [2] 87 cb [2] 88 d1 [2] 96 cc [2] 94 cd [2] 8f cb [2] 93 cc [2] 8f e3 }

  condition:
    any of them
}