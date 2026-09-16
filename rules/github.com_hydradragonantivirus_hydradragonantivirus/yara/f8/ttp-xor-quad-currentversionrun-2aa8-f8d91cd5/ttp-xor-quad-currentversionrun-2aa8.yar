rule TTP_XOR_QUAD_CurrentVersionRun_2aa8 {
  strings:
    $key_2aa8 = { 79 c7 [2] 5d c9 [2] 76 e5 [2] 58 c7 [2] 4c dc [2] 43 c6 [2] 5d db [2] 5f da [2] 44 dc [2] 58 db [2] 44 f4 }

  condition:
    any of them
}