rule TTP_XOR_QUAD_CurrentVersionRun_27b4 {
  strings:
    $key_27b4 = { 74 db [2] 50 d5 [2] 7b f9 [2] 55 db [2] 41 c0 [2] 4e da [2] 50 c7 [2] 52 c6 [2] 49 c0 [2] 55 c7 [2] 49 e8 }

  condition:
    any of them
}