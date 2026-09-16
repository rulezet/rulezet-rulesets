rule TTP_XOR_QUAD_CurrentVersionRun_e59c {
  strings:
    $key_e59c = { b6 f3 [2] 92 fd [2] b9 d1 [2] 97 f3 [2] 83 e8 [2] 8c f2 [2] 92 ef [2] 90 ee [2] 8b e8 [2] 97 ef [2] 8b c0 }

  condition:
    any of them
}