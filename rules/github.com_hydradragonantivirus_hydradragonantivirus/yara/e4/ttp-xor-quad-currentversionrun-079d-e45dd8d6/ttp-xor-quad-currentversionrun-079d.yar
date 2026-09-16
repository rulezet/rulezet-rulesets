rule TTP_XOR_QUAD_CurrentVersionRun_079d {
  strings:
    $key_079d = { 54 f2 [2] 70 fc [2] 5b d0 [2] 75 f2 [2] 61 e9 [2] 6e f3 [2] 70 ee [2] 72 ef [2] 69 e9 [2] 75 ee [2] 69 c1 }

  condition:
    any of them
}