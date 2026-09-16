rule TTP_XOR_QUAD_CurrentVersionRun_e5b4 {
  strings:
    $key_e5b4 = { b6 db [2] 92 d5 [2] b9 f9 [2] 97 db [2] 83 c0 [2] 8c da [2] 92 c7 [2] 90 c6 [2] 8b c0 [2] 97 c7 [2] 8b e8 }

  condition:
    any of them
}