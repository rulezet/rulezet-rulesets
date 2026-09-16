rule TTP_XOR_QUAD_CurrentVersionRun_db9d {
  strings:
    $key_db9d = { 88 f2 [2] ac fc [2] 87 d0 [2] a9 f2 [2] bd e9 [2] b2 f3 [2] ac ee [2] ae ef [2] b5 e9 [2] a9 ee [2] b5 c1 }

  condition:
    any of them
}