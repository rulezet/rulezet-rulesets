rule TTP_XOR_QUAD_CurrentVersionRun_4bbb {
  strings:
    $key_4bbb = { 18 d4 [2] 3c da [2] 17 f6 [2] 39 d4 [2] 2d cf [2] 22 d5 [2] 3c c8 [2] 3e c9 [2] 25 cf [2] 39 c8 [2] 25 e7 }

  condition:
    any of them
}