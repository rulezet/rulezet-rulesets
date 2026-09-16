rule TTP_XOR_QUAD_CurrentVersionRun_55c8 {
  strings:
    $key_55c8 = { 06 a7 [2] 22 a9 [2] 09 85 [2] 27 a7 [2] 33 bc [2] 3c a6 [2] 22 bb [2] 20 ba [2] 3b bc [2] 27 bb [2] 3b 94 }

  condition:
    any of them
}