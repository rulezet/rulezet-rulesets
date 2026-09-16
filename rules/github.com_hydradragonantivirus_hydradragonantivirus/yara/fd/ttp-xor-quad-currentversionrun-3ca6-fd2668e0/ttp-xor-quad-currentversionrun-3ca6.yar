rule TTP_XOR_QUAD_CurrentVersionRun_3ca6 {
  strings:
    $key_3ca6 = { 6f c9 [2] 4b c7 [2] 60 eb [2] 4e c9 [2] 5a d2 [2] 55 c8 [2] 4b d5 [2] 49 d4 [2] 52 d2 [2] 4e d5 [2] 52 fa }

  condition:
    any of them
}