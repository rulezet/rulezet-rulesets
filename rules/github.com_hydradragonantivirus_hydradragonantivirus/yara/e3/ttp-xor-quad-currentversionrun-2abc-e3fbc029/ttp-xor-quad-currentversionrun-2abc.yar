rule TTP_XOR_QUAD_CurrentVersionRun_2abc {
  strings:
    $key_2abc = { 79 d3 [2] 5d dd [2] 76 f1 [2] 58 d3 [2] 4c c8 [2] 43 d2 [2] 5d cf [2] 5f ce [2] 44 c8 [2] 58 cf [2] 44 e0 }

  condition:
    any of them
}