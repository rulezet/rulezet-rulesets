rule TTP_XOR_QUAD_CurrentVersionRun_f1bf {
  strings:
    $key_f1bf = { a2 d0 [2] 86 de [2] ad f2 [2] 83 d0 [2] 97 cb [2] 98 d1 [2] 86 cc [2] 84 cd [2] 9f cb [2] 83 cc [2] 9f e3 }

  condition:
    any of them
}