rule TTP_XOR_QUAD_CurrentVersionRun_3380 {
  strings:
    $key_3380 = { 60 ef [2] 44 e1 [2] 6f cd [2] 41 ef [2] 55 f4 [2] 5a ee [2] 44 f3 [2] 46 f2 [2] 5d f4 [2] 41 f3 [2] 5d dc }

  condition:
    any of them
}