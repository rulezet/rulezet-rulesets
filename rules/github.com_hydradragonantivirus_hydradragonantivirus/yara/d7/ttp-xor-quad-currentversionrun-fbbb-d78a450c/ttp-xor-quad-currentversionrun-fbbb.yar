rule TTP_XOR_QUAD_CurrentVersionRun_fbbb {
  strings:
    $key_fbbb = { a8 d4 [2] 8c da [2] a7 f6 [2] 89 d4 [2] 9d cf [2] 92 d5 [2] 8c c8 [2] 8e c9 [2] 95 cf [2] 89 c8 [2] 95 e7 }

  condition:
    any of them
}