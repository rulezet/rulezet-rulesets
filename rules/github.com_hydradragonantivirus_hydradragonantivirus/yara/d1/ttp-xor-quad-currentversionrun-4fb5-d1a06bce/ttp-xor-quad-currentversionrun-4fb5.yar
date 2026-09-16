rule TTP_XOR_QUAD_CurrentVersionRun_4fb5 {
  strings:
    $key_4fb5 = { 1c da [2] 38 d4 [2] 13 f8 [2] 3d da [2] 29 c1 [2] 26 db [2] 38 c6 [2] 3a c7 [2] 21 c1 [2] 3d c6 [2] 21 e9 }

  condition:
    any of them
}