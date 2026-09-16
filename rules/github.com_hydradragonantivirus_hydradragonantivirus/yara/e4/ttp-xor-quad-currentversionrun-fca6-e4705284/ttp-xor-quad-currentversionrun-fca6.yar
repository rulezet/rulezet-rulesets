rule TTP_XOR_QUAD_CurrentVersionRun_fca6 {
  strings:
    $key_fca6 = { af c9 [2] 8b c7 [2] a0 eb [2] 8e c9 [2] 9a d2 [2] 95 c8 [2] 8b d5 [2] 89 d4 [2] 92 d2 [2] 8e d5 [2] 92 fa }

  condition:
    any of them
}