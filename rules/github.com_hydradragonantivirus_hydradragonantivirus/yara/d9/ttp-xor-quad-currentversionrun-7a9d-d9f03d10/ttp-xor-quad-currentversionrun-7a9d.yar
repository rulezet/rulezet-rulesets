rule TTP_XOR_QUAD_CurrentVersionRun_7a9d {
  strings:
    $key_7a9d = { 29 f2 [2] 0d fc [2] 26 d0 [2] 08 f2 [2] 1c e9 [2] 13 f3 [2] 0d ee [2] 0f ef [2] 14 e9 [2] 08 ee [2] 14 c1 }

  condition:
    any of them
}