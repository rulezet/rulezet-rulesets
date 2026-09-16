rule TTP_XOR_QUAD_CurrentVersionRun_5abc {
  strings:
    $key_5abc = { 09 d3 [2] 2d dd [2] 06 f1 [2] 28 d3 [2] 3c c8 [2] 33 d2 [2] 2d cf [2] 2f ce [2] 34 c8 [2] 28 cf [2] 34 e0 }

  condition:
    any of them
}