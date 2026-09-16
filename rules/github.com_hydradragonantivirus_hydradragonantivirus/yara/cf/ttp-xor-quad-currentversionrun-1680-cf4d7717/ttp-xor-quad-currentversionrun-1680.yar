rule TTP_XOR_QUAD_CurrentVersionRun_1680 {
  strings:
    $key_1680 = { 45 ef [2] 61 e1 [2] 4a cd [2] 64 ef [2] 70 f4 [2] 7f ee [2] 61 f3 [2] 63 f2 [2] 78 f4 [2] 64 f3 [2] 78 dc }

  condition:
    any of them
}