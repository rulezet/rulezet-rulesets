rule TTP_XOR_QUAD_CurrentVersionRun_469d {
  strings:
    $key_469d = { 15 f2 [2] 31 fc [2] 1a d0 [2] 34 f2 [2] 20 e9 [2] 2f f3 [2] 31 ee [2] 33 ef [2] 28 e9 [2] 34 ee [2] 28 c1 }

  condition:
    any of them
}