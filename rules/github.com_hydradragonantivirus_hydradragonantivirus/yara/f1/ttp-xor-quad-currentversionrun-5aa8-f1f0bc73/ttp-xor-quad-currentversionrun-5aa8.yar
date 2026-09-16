rule TTP_XOR_QUAD_CurrentVersionRun_5aa8 {
  strings:
    $key_5aa8 = { 09 c7 [2] 2d c9 [2] 06 e5 [2] 28 c7 [2] 3c dc [2] 33 c6 [2] 2d db [2] 2f da [2] 34 dc [2] 28 db [2] 34 f4 }

  condition:
    any of them
}