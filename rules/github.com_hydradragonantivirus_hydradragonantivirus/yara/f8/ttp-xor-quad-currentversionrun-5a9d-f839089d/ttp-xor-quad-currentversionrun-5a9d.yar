rule TTP_XOR_QUAD_CurrentVersionRun_5a9d {
  strings:
    $key_5a9d = { 09 f2 [2] 2d fc [2] 06 d0 [2] 28 f2 [2] 3c e9 [2] 33 f3 [2] 2d ee [2] 2f ef [2] 34 e9 [2] 28 ee [2] 34 c1 }

  condition:
    any of them
}