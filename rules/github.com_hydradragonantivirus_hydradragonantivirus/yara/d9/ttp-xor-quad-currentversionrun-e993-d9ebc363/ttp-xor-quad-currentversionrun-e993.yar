rule TTP_XOR_QUAD_CurrentVersionRun_e993 {
  strings:
    $key_e993 = { ba fc [2] 9e f2 [2] b5 de [2] 9b fc [2] 8f e7 [2] 80 fd [2] 9e e0 [2] 9c e1 [2] 87 e7 [2] 9b e0 [2] 87 cf }

  condition:
    any of them
}