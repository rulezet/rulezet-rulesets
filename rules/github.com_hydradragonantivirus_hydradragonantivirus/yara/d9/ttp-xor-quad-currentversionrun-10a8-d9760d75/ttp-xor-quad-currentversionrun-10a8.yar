rule TTP_XOR_QUAD_CurrentVersionRun_10a8 {
  strings:
    $key_10a8 = { 43 c7 [2] 67 c9 [2] 4c e5 [2] 62 c7 [2] 76 dc [2] 79 c6 [2] 67 db [2] 65 da [2] 7e dc [2] 62 db [2] 7e f4 }

  condition:
    any of them
}