rule TTP_XOR_QUAD_CurrentVersionRun_29b6 {
  strings:
    $key_29b6 = { 7a d9 [2] 5e d7 [2] 75 fb [2] 5b d9 [2] 4f c2 [2] 40 d8 [2] 5e c5 [2] 5c c4 [2] 47 c2 [2] 5b c5 [2] 47 ea }

  condition:
    any of them
}