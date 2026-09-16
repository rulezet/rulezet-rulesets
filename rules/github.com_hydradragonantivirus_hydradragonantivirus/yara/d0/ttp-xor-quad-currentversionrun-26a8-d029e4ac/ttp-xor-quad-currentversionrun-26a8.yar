rule TTP_XOR_QUAD_CurrentVersionRun_26a8 {
  strings:
    $key_26a8 = { 75 c7 [2] 51 c9 [2] 7a e5 [2] 54 c7 [2] 40 dc [2] 4f c6 [2] 51 db [2] 53 da [2] 48 dc [2] 54 db [2] 48 f4 }

  condition:
    any of them
}