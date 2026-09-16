rule TTP_XOR_QUAD_CurrentVersionRun_569d {
  strings:
    $key_569d = { 05 f2 [2] 21 fc [2] 0a d0 [2] 24 f2 [2] 30 e9 [2] 3f f3 [2] 21 ee [2] 23 ef [2] 38 e9 [2] 24 ee [2] 38 c1 }

  condition:
    any of them
}