rule TTP_XOR_QUAD_CurrentVersionRun_10a9 {
  strings:
    $key_10a9 = { 43 c6 [2] 67 c8 [2] 4c e4 [2] 62 c6 [2] 76 dd [2] 79 c7 [2] 67 da [2] 65 db [2] 7e dd [2] 62 da [2] 7e f5 }

  condition:
    any of them
}