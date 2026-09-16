rule TTP_XOR_QUAD_CurrentVersionRun_769b {
  strings:
    $key_769b = { 25 f4 [2] 01 fa [2] 2a d6 [2] 04 f4 [2] 10 ef [2] 1f f5 [2] 01 e8 [2] 03 e9 [2] 18 ef [2] 04 e8 [2] 18 c7 }

  condition:
    any of them
}