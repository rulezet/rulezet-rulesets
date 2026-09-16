rule TTP_XOR_QUAD_CurrentVersionRun_f4bf {
  strings:
    $key_f4bf = { a7 d0 [2] 83 de [2] a8 f2 [2] 86 d0 [2] 92 cb [2] 9d d1 [2] 83 cc [2] 81 cd [2] 9a cb [2] 86 cc [2] 9a e3 }

  condition:
    any of them
}