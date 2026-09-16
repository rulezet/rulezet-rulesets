rule TTP_XOR_QUAD_CurrentVersionRun_e287 {
  strings:
    $key_e287 = { b1 e8 [2] 95 e6 [2] be ca [2] 90 e8 [2] 84 f3 [2] 8b e9 [2] 95 f4 [2] 97 f5 [2] 8c f3 [2] 90 f4 [2] 8c db }

  condition:
    any of them
}