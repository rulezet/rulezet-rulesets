rule TTP_XOR_QUAD_CurrentVersionRun_e5bf {
  strings:
    $key_e5bf = { b6 d0 [2] 92 de [2] b9 f2 [2] 97 d0 [2] 83 cb [2] 8c d1 [2] 92 cc [2] 90 cd [2] 8b cb [2] 97 cc [2] 8b e3 }

  condition:
    any of them
}