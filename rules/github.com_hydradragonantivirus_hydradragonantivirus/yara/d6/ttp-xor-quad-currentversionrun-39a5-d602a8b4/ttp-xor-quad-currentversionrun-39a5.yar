rule TTP_XOR_QUAD_CurrentVersionRun_39a5 {
  strings:
    $key_39a5 = { 6a ca [2] 4e c4 [2] 65 e8 [2] 4b ca [2] 5f d1 [2] 50 cb [2] 4e d6 [2] 4c d7 [2] 57 d1 [2] 4b d6 [2] 57 f9 }

  condition:
    any of them
}