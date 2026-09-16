rule TTP_XOR_QUAD_CurrentVersionRun_01b5 {
  strings:
    $key_01b5 = { 52 da [2] 76 d4 [2] 5d f8 [2] 73 da [2] 67 c1 [2] 68 db [2] 76 c6 [2] 74 c7 [2] 6f c1 [2] 73 c6 [2] 6f e9 }

  condition:
    any of them
}