rule TTP_XOR_QUAD_CurrentVersionRun_359d {
  strings:
    $key_359d = { 66 f2 [2] 42 fc [2] 69 d0 [2] 47 f2 [2] 53 e9 [2] 5c f3 [2] 42 ee [2] 40 ef [2] 5b e9 [2] 47 ee [2] 5b c1 }

  condition:
    any of them
}