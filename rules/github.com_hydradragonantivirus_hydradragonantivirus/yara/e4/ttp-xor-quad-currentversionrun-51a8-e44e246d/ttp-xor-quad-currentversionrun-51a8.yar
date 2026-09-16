rule TTP_XOR_QUAD_CurrentVersionRun_51a8 {
  strings:
    $key_51a8 = { 02 c7 [2] 26 c9 [2] 0d e5 [2] 23 c7 [2] 37 dc [2] 38 c6 [2] 26 db [2] 24 da [2] 3f dc [2] 23 db [2] 3f f4 }

  condition:
    any of them
}