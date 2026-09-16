rule TTP_XOR_QUAD_CurrentVersionRun_30a9 {
  strings:
    $key_30a9 = { 63 c6 [2] 47 c8 [2] 6c e4 [2] 42 c6 [2] 56 dd [2] 59 c7 [2] 47 da [2] 45 db [2] 5e dd [2] 42 da [2] 5e f5 }

  condition:
    any of them
}