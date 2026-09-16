rule TTP_XOR_QUAD_CurrentVersionRun_4180 {
  strings:
    $key_4180 = { 12 ef [2] 36 e1 [2] 1d cd [2] 33 ef [2] 27 f4 [2] 28 ee [2] 36 f3 [2] 34 f2 [2] 2f f4 [2] 33 f3 [2] 2f dc }

  condition:
    any of them
}