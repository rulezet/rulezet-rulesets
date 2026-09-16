rule TTP_XOR_QUAD_CurrentVersionRun_2680 {
  strings:
    $key_2680 = { 75 ef [2] 51 e1 [2] 7a cd [2] 54 ef [2] 40 f4 [2] 4f ee [2] 51 f3 [2] 53 f2 [2] 48 f4 [2] 54 f3 [2] 48 dc }

  condition:
    any of them
}