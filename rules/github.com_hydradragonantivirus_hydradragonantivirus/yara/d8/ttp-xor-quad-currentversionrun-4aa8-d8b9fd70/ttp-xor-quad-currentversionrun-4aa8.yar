rule TTP_XOR_QUAD_CurrentVersionRun_4aa8 {
  strings:
    $key_4aa8 = { 19 c7 [2] 3d c9 [2] 16 e5 [2] 38 c7 [2] 2c dc [2] 23 c6 [2] 3d db [2] 3f da [2] 24 dc [2] 38 db [2] 24 f4 }

  condition:
    any of them
}