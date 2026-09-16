rule TTP_XOR_QUAD_CurrentVersionRun_eb96 {
  strings:
    $key_eb96 = { b8 f9 [2] 9c f7 [2] b7 db [2] 99 f9 [2] 8d e2 [2] 82 f8 [2] 9c e5 [2] 9e e4 [2] 85 e2 [2] 99 e5 [2] 85 ca }

  condition:
    any of them
}