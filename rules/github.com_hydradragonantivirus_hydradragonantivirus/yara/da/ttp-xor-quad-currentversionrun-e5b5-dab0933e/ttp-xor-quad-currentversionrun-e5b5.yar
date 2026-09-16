rule TTP_XOR_QUAD_CurrentVersionRun_e5b5 {
  strings:
    $key_e5b5 = { b6 da [2] 92 d4 [2] b9 f8 [2] 97 da [2] 83 c1 [2] 8c db [2] 92 c6 [2] 90 c7 [2] 8b c1 [2] 97 c6 [2] 8b e9 }

  condition:
    any of them
}