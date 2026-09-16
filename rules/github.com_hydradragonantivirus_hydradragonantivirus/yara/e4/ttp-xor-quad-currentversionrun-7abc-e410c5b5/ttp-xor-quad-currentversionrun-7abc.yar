rule TTP_XOR_QUAD_CurrentVersionRun_7abc {
  strings:
    $key_7abc = { 29 d3 [2] 0d dd [2] 26 f1 [2] 08 d3 [2] 1c c8 [2] 13 d2 [2] 0d cf [2] 0f ce [2] 14 c8 [2] 08 cf [2] 14 e0 }

  condition:
    any of them
}