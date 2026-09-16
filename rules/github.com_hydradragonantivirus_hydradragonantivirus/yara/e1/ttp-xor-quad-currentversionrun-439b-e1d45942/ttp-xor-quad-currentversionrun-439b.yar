rule TTP_XOR_QUAD_CurrentVersionRun_439b {
  strings:
    $key_439b = { 10 f4 [2] 34 fa [2] 1f d6 [2] 31 f4 [2] 25 ef [2] 2a f5 [2] 34 e8 [2] 36 e9 [2] 2d ef [2] 31 e8 [2] 2d c7 }

  condition:
    any of them
}